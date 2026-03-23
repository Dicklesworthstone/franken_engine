// Allow dead code: this is test infrastructure; not all items are used yet.
#![allow(dead_code)]
//! Deterministic E2E harness substrate for FrankenEngine.
//!
//! This module provides:
//! - deterministic runner (seeded randomness + virtual time)
//! - fixture store (content-addressed JSON fixtures)
//! - structured log assertions
//! - artifact collection (manifest + JSONL events + JSON/Markdown reports)
//! - replay verification (digest + event equality)

use std::collections::BTreeMap;
use std::error::Error;
use std::fmt;
use std::fs;
use std::io;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

/// Minimal virtual clock for deterministic tests.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct VirtualClock {
    now_micros: u64,
}

impl VirtualClock {
    /// Creates a clock pinned to a deterministic start instant.
    pub fn new(now_micros: u64) -> Self {
        Self { now_micros }
    }

    /// Returns the current virtual timestamp in microseconds.
    pub fn now_micros(self) -> u64 {
        self.now_micros
    }

    /// Advances the clock by a deterministic delta.
    pub fn advance(&mut self, delta_micros: u64) {
        self.now_micros = self.now_micros.saturating_add(delta_micros);
    }
}

/// XorShift-based deterministic RNG suitable for reproducible tests.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct DeterministicRng {
    state: u64,
}

impl DeterministicRng {
    pub fn seeded(seed: u64) -> Self {
        // Avoid all-zero xorshift state.
        let state = if seed == 0 {
            0x9E37_79B9_7F4A_7C15
        } else {
            seed
        };
        Self { state }
    }

    pub fn next_u64(&mut self) -> u64 {
        // xorshift64*
        let mut x = self.state;
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        self.state = x;
        x.wrapping_mul(0x2545F4914F6CDD1D)
    }
}

/// One deterministic step in an E2E fixture.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ScenarioStep {
    pub component: String,
    pub event: String,
    #[serde(default)]
    pub advance_micros: u64,
    /// Optional knobs used to force deterministic error/outcome classes.
    #[serde(default)]
    pub metadata: BTreeMap<String, String>,
}

/// Expected event shape for log assertions and replay baselines.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExpectedEvent {
    pub component: String,
    pub event: String,
    pub outcome: String,
    #[serde(default)]
    pub error_code: Option<String>,
}

/// Versioned fixture contract for deterministic E2E runs.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TestFixture {
    pub fixture_id: String,
    pub fixture_version: u32,
    pub seed: u64,
    pub virtual_time_start_micros: u64,
    pub policy_id: String,
    pub steps: Vec<ScenarioStep>,
    #[serde(default)]
    pub expected_events: Vec<ExpectedEvent>,
    #[serde(default)]
    pub determinism_check: bool,
}

impl TestFixture {
    pub const CURRENT_VERSION: u32 = 1;

    pub fn validate(&self) -> Result<(), FixtureValidationError> {
        if self.fixture_id.trim().is_empty() {
            return Err(FixtureValidationError::MissingFixtureId);
        }
        if self.fixture_version != Self::CURRENT_VERSION {
            return Err(FixtureValidationError::UnsupportedVersion {
                expected: Self::CURRENT_VERSION,
                actual: self.fixture_version,
            });
        }
        if self.policy_id.trim().is_empty() {
            return Err(FixtureValidationError::MissingPolicyId);
        }
        if self.steps.is_empty() {
            return Err(FixtureValidationError::MissingSteps);
        }
        for (idx, step) in self.steps.iter().enumerate() {
            if step.component.trim().is_empty() {
                return Err(FixtureValidationError::InvalidStep {
                    index: idx,
                    reason: "component is empty".to_string(),
                });
            }
            if step.event.trim().is_empty() {
                return Err(FixtureValidationError::InvalidStep {
                    index: idx,
                    reason: "event is empty".to_string(),
                });
            }
        }
        Ok(())
    }
}

/// Structured event emitted by deterministic harness execution.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HarnessEvent {
    pub trace_id: String,
    pub decision_id: String,
    pub policy_id: String,
    pub component: String,
    pub event: String,
    pub outcome: String,
    pub error_code: Option<String>,
    pub sequence: u64,
    pub virtual_time_micros: u64,
}

/// Replayable run output for a fixture.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RunResult {
    pub fixture_id: String,
    pub run_id: String,
    pub seed: u64,
    pub start_virtual_time_micros: u64,
    pub end_virtual_time_micros: u64,
    pub random_transcript: Vec<u64>,
    pub events: Vec<HarnessEvent>,
    pub output_digest: String,
}

/// Deterministic replay-input validation failure classes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReplayInputErrorCode {
    MissingModelSnapshot,
    PartialTrace,
    CorruptedTranscript,
}

/// Deterministic replay-input validation error.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReplayInputError {
    pub code: ReplayInputErrorCode,
    pub message: String,
}

impl fmt::Display for ReplayInputError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}: {}", self.code.as_str(), self.message)
    }
}

impl Error for ReplayInputError {}

impl ReplayInputErrorCode {
    fn as_str(self) -> &'static str {
        match self {
            Self::MissingModelSnapshot => "missing_model_snapshot",
            Self::PartialTrace => "partial_trace",
            Self::CorruptedTranscript => "corrupted_transcript",
        }
    }
}

/// Deterministic linkage row for replay evidence.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EvidenceLinkageRecord {
    pub trace_id: String,
    pub decision_id: String,
    pub policy_id: String,
    pub event_sequence: u64,
    pub evidence_hash: String,
}

/// Deterministic runner configuration.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DeterministicRunnerConfig {
    pub trace_prefix: String,
}

impl Default for DeterministicRunnerConfig {
    fn default() -> Self {
        Self {
            trace_prefix: "trace".to_string(),
        }
    }
}

/// Deterministic test runner.
#[derive(Debug, Clone, Default)]
pub struct DeterministicRunner {
    pub config: DeterministicRunnerConfig,
}

impl DeterministicRunner {
    pub fn run_fixture(&self, fixture: &TestFixture) -> Result<RunResult, FixtureValidationError> {
        fixture.validate()?;

        let mut clock = VirtualClock::new(fixture.virtual_time_start_micros);
        let mut rng = DeterministicRng::seeded(fixture.seed);
        let trace_id = format!("{}-{}", self.config.trace_prefix, fixture.fixture_id);

        let mut random_transcript = Vec::with_capacity(fixture.steps.len());
        let mut events = Vec::with_capacity(fixture.steps.len());

        for (idx, step) in fixture.steps.iter().enumerate() {
            clock.advance(step.advance_micros);
            let sample = rng.next_u64();
            random_transcript.push(sample);

            let error_code = step.metadata.get("error_code").cloned();
            let outcome = if error_code.is_some() {
                "error".to_string()
            } else {
                step.metadata
                    .get("outcome")
                    .cloned()
                    .unwrap_or_else(|| "ok".to_string())
            };

            events.push(HarnessEvent {
                trace_id: trace_id.clone(),
                decision_id: format!("decision-{:04}", idx),
                policy_id: fixture.policy_id.clone(),
                component: step.component.clone(),
                event: step.event.clone(),
                outcome,
                error_code,
                sequence: idx as u64,
                virtual_time_micros: clock.now_micros(),
            });
        }

        let digest = digest_run(
            &fixture.fixture_id,
            fixture.seed,
            &random_transcript,
            &events,
        );
        let run_id = format!(
            "run-{}-{}",
            sanitize_label(&fixture.fixture_id),
            &digest[..12.min(digest.len())]
        );

        Ok(RunResult {
            fixture_id: fixture.fixture_id.clone(),
            run_id,
            seed: fixture.seed,
            start_virtual_time_micros: fixture.virtual_time_start_micros,
            end_virtual_time_micros: clock.now_micros(),
            random_transcript,
            events,
            output_digest: digest,
        })
    }
}

/// Fixture-validation failures.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FixtureValidationError {
    MissingFixtureId,
    MissingPolicyId,
    MissingSteps,
    UnsupportedVersion { expected: u32, actual: u32 },
    InvalidStep { index: usize, reason: String },
}

impl fmt::Display for FixtureValidationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::MissingFixtureId => write!(f, "fixture_id is required"),
            Self::MissingPolicyId => write!(f, "policy_id is required"),
            Self::MissingSteps => write!(f, "fixture must contain at least one step"),
            Self::UnsupportedVersion { expected, actual } => {
                write!(
                    f,
                    "unsupported fixture version: expected {expected}, got {actual}"
                )
            }
            Self::InvalidStep { index, reason } => {
                write!(f, "invalid step at index {index}: {reason}")
            }
        }
    }
}

impl Error for FixtureValidationError {}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct LegacyFixtureV0 {
    fixture_id: String,
    fixture_version: u32,
    seed: u64,
    virtual_time_start_micros: u64,
    policy_id: String,
    steps: Vec<ScenarioStep>,
}

/// Fixture migration failures for schema-evolution replay support.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum FixtureMigrationError {
    InvalidFixturePayload { message: String },
    UnsupportedVersion { expected: u32, actual: u32 },
    InvalidMigratedFixture { message: String },
}

impl fmt::Display for FixtureMigrationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidFixturePayload { message } => {
                write!(f, "invalid fixture payload: {message}")
            }
            Self::UnsupportedVersion { expected, actual } => write!(
                f,
                "unsupported fixture version: expected {expected} (or migratable 0), got {actual}"
            ),
            Self::InvalidMigratedFixture { message } => {
                write!(f, "invalid migrated fixture: {message}")
            }
        }
    }
}

impl Error for FixtureMigrationError {}

/// Parses fixture payloads and migrates legacy schema versions when supported.
pub fn parse_fixture_with_migration(bytes: &[u8]) -> Result<TestFixture, FixtureMigrationError> {
    let value: serde_json::Value = serde_json::from_slice(bytes).map_err(|err| {
        FixtureMigrationError::InvalidFixturePayload {
            message: err.to_string(),
        }
    })?;

    let version = value
        .get("fixture_version")
        .and_then(|raw| raw.as_u64())
        .ok_or_else(|| FixtureMigrationError::InvalidFixturePayload {
            message: "missing fixture_version".to_string(),
        })? as u32;

    if version == TestFixture::CURRENT_VERSION {
        let fixture: TestFixture = serde_json::from_value(value).map_err(|err| {
            FixtureMigrationError::InvalidFixturePayload {
                message: err.to_string(),
            }
        })?;
        fixture
            .validate()
            .map_err(|err| FixtureMigrationError::InvalidMigratedFixture {
                message: err.to_string(),
            })?;
        return Ok(fixture);
    }

    if version == 0 {
        let legacy: LegacyFixtureV0 = serde_json::from_value(value).map_err(|err| {
            FixtureMigrationError::InvalidFixturePayload {
                message: err.to_string(),
            }
        })?;
        let migrated = TestFixture {
            fixture_id: legacy.fixture_id,
            fixture_version: TestFixture::CURRENT_VERSION,
            seed: legacy.seed,
            virtual_time_start_micros: legacy.virtual_time_start_micros,
            policy_id: legacy.policy_id,
            steps: legacy.steps,
            expected_events: Vec::new(),
            determinism_check: true,
        };
        migrated
            .validate()
            .map_err(|err| FixtureMigrationError::InvalidMigratedFixture {
                message: err.to_string(),
            })?;
        return Ok(migrated);
    }

    Err(FixtureMigrationError::UnsupportedVersion {
        expected: TestFixture::CURRENT_VERSION,
        actual: version,
    })
}

/// Content-addressed fixture store.
#[derive(Debug, Clone)]
pub struct FixtureStore {
    root: PathBuf,
}

impl FixtureStore {
    pub fn new(root: impl Into<PathBuf>) -> io::Result<Self> {
        let root = root.into();
        fs::create_dir_all(&root)?;
        Ok(Self { root })
    }

    pub fn save_fixture(&self, fixture: &TestFixture) -> io::Result<PathBuf> {
        fixture
            .validate()
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e))?;

        let payload = canonical_json_bytes(fixture)?;
        let digest = digest_hex(&payload);
        let filename = format!(
            "{}-{}.json",
            sanitize_label(&fixture.fixture_id),
            &digest[..16]
        );
        let path = self.root.join(filename);
        write_atomic(&path, &payload)?;
        Ok(path)
    }

    pub fn load_fixture(&self, path: impl AsRef<Path>) -> io::Result<TestFixture> {
        let bytes = fs::read(path.as_ref())?;
        parse_fixture_with_migration(&bytes)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))
    }
}

/// Structured log expectation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LogExpectation {
    pub component: String,
    pub event: String,
    pub outcome: String,
    pub error_code: Option<String>,
}

/// Log-assertion mismatch.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LogAssertionError {
    pub missing: Vec<LogExpectation>,
}

impl fmt::Display for LogAssertionError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "missing {} expected log events", self.missing.len())
    }
}

impl Error for LogAssertionError {}

/// Validates that each expected structured log event has a matching emission.
pub fn assert_structured_logs(
    events: &[HarnessEvent],
    expectations: &[LogExpectation],
) -> Result<(), LogAssertionError> {
    let mut missing = Vec::new();
    for expected in expectations {
        let found = events.iter().any(|actual| {
            actual.component == expected.component
                && actual.event == expected.event
                && actual.outcome == expected.outcome
                && actual.error_code == expected.error_code
        });
        if !found {
            missing.push(expected.clone());
        }
    }
    if missing.is_empty() {
        Ok(())
    } else {
        Err(LogAssertionError { missing })
    }
}

/// Replay-verification result.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReplayMismatchKind {
    Digest,
    EventStream,
    RandomTranscript,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReplayVerification {
    pub matches: bool,
    pub expected_digest: String,
    pub actual_digest: String,
    pub reason: Option<String>,
    pub mismatch_kind: Option<ReplayMismatchKind>,
    pub diverged_event_sequence: Option<u64>,
    pub transcript_mismatch_index: Option<usize>,
    pub expected_event_count: usize,
    pub actual_event_count: usize,
    pub expected_transcript_len: usize,
    pub actual_transcript_len: usize,
}

/// Replay performance check against virtual-time budget.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReplayPerformance {
    pub virtual_duration_micros: u64,
    pub wall_duration_micros: u64,
    pub faster_than_realtime: bool,
    pub speedup_milli: u64,
}

/// Minimal target-environment fingerprint for cross-machine replay diagnosis.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReplayEnvironmentFingerprint {
    pub os: String,
    pub architecture: String,
    pub family: String,
    pub pointer_width_bits: u8,
    pub endian: String,
}

impl ReplayEnvironmentFingerprint {
    pub fn local() -> Self {
        Self {
            os: std::env::consts::OS.to_string(),
            architecture: std::env::consts::ARCH.to_string(),
            family: std::env::consts::FAMILY.to_string(),
            pointer_width_bits: if cfg!(target_pointer_width = "64") {
                64
            } else if cfg!(target_pointer_width = "32") {
                32
            } else if cfg!(target_pointer_width = "16") {
                16
            } else {
                0
            },
            endian: if cfg!(target_endian = "little") {
                "little".to_string()
            } else {
                "big".to_string()
            },
        }
    }
}

/// Cross-machine replay diagnosis with explicit environment deltas.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CrossMachineReplayDiagnosis {
    pub cross_machine_match: bool,
    pub replay_verification: ReplayVerification,
    pub expected_environment: ReplayEnvironmentFingerprint,
    pub actual_environment: ReplayEnvironmentFingerprint,
    pub environment_mismatches: Vec<String>,
    pub diagnosis: Option<String>,
}

fn environment_mismatch_fields(
    expected: &ReplayEnvironmentFingerprint,
    actual: &ReplayEnvironmentFingerprint,
) -> Vec<String> {
    let mut mismatches = Vec::new();
    if expected.os != actual.os {
        mismatches.push("os".to_string());
    }
    if expected.architecture != actual.architecture {
        mismatches.push("architecture".to_string());
    }
    if expected.family != actual.family {
        mismatches.push("family".to_string());
    }
    if expected.pointer_width_bits != actual.pointer_width_bits {
        mismatches.push("pointer_width_bits".to_string());
    }
    if expected.endian != actual.endian {
        mismatches.push("endian".to_string());
    }
    mismatches
}

fn first_event_mismatch_index(expected: &[HarnessEvent], actual: &[HarnessEvent]) -> Option<u64> {
    let max_len = expected.len().max(actual.len());
    (0..max_len)
        .find(|&idx| expected.get(idx) != actual.get(idx))
        .map(|idx| idx as u64)
}

fn first_transcript_mismatch(expected: &[u64], actual: &[u64]) -> Option<usize> {
    let max_len = expected.len().max(actual.len());
    (0..max_len).find(|&idx| expected.get(idx) != actual.get(idx))
}

/// Verifies deterministic replay equivalence between two run outputs.
pub fn verify_replay(expected: &RunResult, actual: &RunResult) -> ReplayVerification {
    let digest_matches = expected.output_digest == actual.output_digest;
    let events_match = expected.events == actual.events;
    let transcript_matches = expected.random_transcript == actual.random_transcript;
    let diverged_event_sequence = first_event_mismatch_index(&expected.events, &actual.events);
    let transcript_mismatch_index =
        first_transcript_mismatch(&expected.random_transcript, &actual.random_transcript);
    let matches = digest_matches && events_match && transcript_matches;

    let (reason, mismatch_kind) = if matches {
        (None, None)
    } else if !digest_matches {
        (
            Some("digest mismatch".to_string()),
            Some(ReplayMismatchKind::Digest),
        )
    } else if !events_match {
        (
            Some("event stream mismatch".to_string()),
            Some(ReplayMismatchKind::EventStream),
        )
    } else {
        (
            Some("random transcript mismatch".to_string()),
            Some(ReplayMismatchKind::RandomTranscript),
        )
    };

    ReplayVerification {
        matches,
        expected_digest: expected.output_digest.clone(),
        actual_digest: actual.output_digest.clone(),
        reason,
        mismatch_kind,
        diverged_event_sequence,
        transcript_mismatch_index,
        expected_event_count: expected.events.len(),
        actual_event_count: actual.events.len(),
        expected_transcript_len: expected.random_transcript.len(),
        actual_transcript_len: actual.random_transcript.len(),
    }
}

/// Evaluates replay speed against the fixture's virtual-time span.
pub fn evaluate_replay_performance(
    result: &RunResult,
    wall_duration_micros: u64,
) -> ReplayPerformance {
    let virtual_duration_micros = result
        .end_virtual_time_micros
        .saturating_sub(result.start_virtual_time_micros);
    let faster_than_realtime = wall_duration_micros <= virtual_duration_micros;
    let speedup_milli = if wall_duration_micros == 0 {
        u64::MAX
    } else {
        let ratio_milli =
            (u128::from(virtual_duration_micros) * 1000) / u128::from(wall_duration_micros);
        ratio_milli.min(u128::from(u64::MAX)) as u64
    };

    ReplayPerformance {
        virtual_duration_micros,
        wall_duration_micros,
        faster_than_realtime,
        speedup_milli,
    }
}

fn digest_harness_event(event: &HarnessEvent) -> String {
    match serde_json::to_vec(event) {
        Ok(bytes) => digest_hex(&bytes),
        Err(e) => format!("digest-error-{:016x}", fnv1a64(e.to_string().as_bytes())),
    }
}

/// Builds deterministic evidence-linkage rows for all run events.
pub fn build_evidence_linkage(events: &[HarnessEvent]) -> Vec<EvidenceLinkageRecord> {
    events
        .iter()
        .map(|event| EvidenceLinkageRecord {
            trace_id: event.trace_id.clone(),
            decision_id: event.decision_id.clone(),
            policy_id: event.policy_id.clone(),
            event_sequence: event.sequence,
            evidence_hash: digest_harness_event(event),
        })
        .collect()
}

/// Validates deterministic replay input requirements and emits stable error codes.
pub fn validate_replay_input(
    result: &RunResult,
    model_snapshot_pointer: Option<&str>,
) -> Result<(), ReplayInputError> {
    match model_snapshot_pointer {
        Some(pointer) if !pointer.trim().is_empty() => {}
        _ => {
            return Err(ReplayInputError {
                code: ReplayInputErrorCode::MissingModelSnapshot,
                message: "model snapshot pointer is required for replay".to_string(),
            });
        }
    }

    for (idx, event) in result.events.iter().enumerate() {
        let expected_sequence = idx as u64;
        if event.sequence != expected_sequence {
            return Err(ReplayInputError {
                code: ReplayInputErrorCode::PartialTrace,
                message: format!(
                    "event sequence gap at index {idx}: expected {expected_sequence}, got {}",
                    event.sequence
                ),
            });
        }
        if event.trace_id.trim().is_empty() {
            return Err(ReplayInputError {
                code: ReplayInputErrorCode::PartialTrace,
                message: format!("event at index {idx} missing trace_id"),
            });
        }
        if event.decision_id.trim().is_empty() {
            return Err(ReplayInputError {
                code: ReplayInputErrorCode::PartialTrace,
                message: format!("event at index {idx} missing decision_id"),
            });
        }
        if event.policy_id.trim().is_empty() {
            return Err(ReplayInputError {
                code: ReplayInputErrorCode::PartialTrace,
                message: format!("event at index {idx} missing policy_id"),
            });
        }
    }

    if result.random_transcript.len() != result.events.len() {
        return Err(ReplayInputError {
            code: ReplayInputErrorCode::CorruptedTranscript,
            message: format!(
                "random transcript length mismatch: expected {}, got {}",
                result.events.len(),
                result.random_transcript.len()
            ),
        });
    }

    let recomputed_digest = digest_run(
        &result.fixture_id,
        result.seed,
        &result.random_transcript,
        &result.events,
    );
    if recomputed_digest != result.output_digest {
        return Err(ReplayInputError {
            code: ReplayInputErrorCode::CorruptedTranscript,
            message: format!(
                "run digest mismatch: expected {}, got {}",
                result.output_digest, recomputed_digest
            ),
        });
    }

    Ok(())
}

/// Produces explicit replay diagnosis for runs executed on potentially different machines.
pub fn diagnose_cross_machine_replay(
    expected: &RunResult,
    actual: &RunResult,
    expected_environment: &ReplayEnvironmentFingerprint,
    actual_environment: &ReplayEnvironmentFingerprint,
) -> CrossMachineReplayDiagnosis {
    let replay_verification = verify_replay(expected, actual);
    let environment_mismatches =
        environment_mismatch_fields(expected_environment, actual_environment);
    let diagnosis = if replay_verification.matches {
        if environment_mismatches.is_empty() {
            None
        } else {
            Some(format!(
                "replay matched across environment deltas: {}",
                environment_mismatches.join(", ")
            ))
        }
    } else {
        let replay_reason = replay_verification
            .reason
            .clone()
            .unwrap_or_else(|| "unknown replay mismatch".to_string());
        if environment_mismatches.is_empty() {
            Some(format!("replay mismatch: {replay_reason}"))
        } else {
            Some(format!(
                "replay mismatch: {replay_reason}; environment mismatch fields: {}",
                environment_mismatches.join(", ")
            ))
        }
    };

    CrossMachineReplayDiagnosis {
        cross_machine_match: replay_verification.matches,
        replay_verification,
        expected_environment: expected_environment.clone(),
        actual_environment: actual_environment.clone(),
        environment_mismatches,
        diagnosis,
    }
}

/// Counterfactual replay delta summary.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CounterfactualDivergenceKind {
    EventMismatch,
    MissingBaselineEvent,
    MissingCounterfactualEvent,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CounterfactualDivergenceSample {
    pub sequence: u64,
    pub kind: CounterfactualDivergenceKind,
    pub baseline_component: Option<String>,
    pub counterfactual_component: Option<String>,
    pub baseline_event: Option<String>,
    pub counterfactual_event: Option<String>,
    pub baseline_outcome: Option<String>,
    pub counterfactual_outcome: Option<String>,
    pub baseline_error_code: Option<String>,
    pub counterfactual_error_code: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CounterfactualDelta {
    pub baseline_run_id: String,
    pub counterfactual_run_id: String,
    pub digest_changed: bool,
    pub diverged_at_sequence: Option<u64>,
    pub changed_events: usize,
    pub changed_outcomes: usize,
    pub changed_error_codes: usize,
    pub baseline_event_count: usize,
    pub counterfactual_event_count: usize,
    pub transcript_changed: bool,
    pub transcript_diverged_at_index: Option<usize>,
    pub divergence_samples: Vec<CounterfactualDivergenceSample>,
}

/// Compares baseline and counterfactual runs and summarizes divergences.
pub fn compare_counterfactual(
    baseline: &RunResult,
    counterfactual: &RunResult,
) -> CounterfactualDelta {
    const MAX_DIVERGENCE_SAMPLES: usize = 8;

    let mut diverged_at_sequence = None;
    let mut changed_events = 0usize;
    let mut changed_outcomes = 0usize;
    let mut changed_error_codes = 0usize;
    let mut divergence_samples = Vec::new();
    let transcript_diverged_at_index = first_transcript_mismatch(
        &baseline.random_transcript,
        &counterfactual.random_transcript,
    );

    let max_len = baseline.events.len().max(counterfactual.events.len());
    for idx in 0..max_len {
        let base = baseline.events.get(idx);
        let alt = counterfactual.events.get(idx);
        match (base, alt) {
            (Some(base_event), Some(alt_event)) => {
                if base_event != alt_event {
                    changed_events += 1;
                    if diverged_at_sequence.is_none() {
                        diverged_at_sequence = Some(idx as u64);
                    }
                    if divergence_samples.len() < MAX_DIVERGENCE_SAMPLES {
                        divergence_samples.push(CounterfactualDivergenceSample {
                            sequence: idx as u64,
                            kind: CounterfactualDivergenceKind::EventMismatch,
                            baseline_component: Some(base_event.component.clone()),
                            counterfactual_component: Some(alt_event.component.clone()),
                            baseline_event: Some(base_event.event.clone()),
                            counterfactual_event: Some(alt_event.event.clone()),
                            baseline_outcome: Some(base_event.outcome.clone()),
                            counterfactual_outcome: Some(alt_event.outcome.clone()),
                            baseline_error_code: base_event.error_code.clone(),
                            counterfactual_error_code: alt_event.error_code.clone(),
                        });
                    }
                }
                if base_event.outcome != alt_event.outcome {
                    changed_outcomes += 1;
                }
                if base_event.error_code != alt_event.error_code {
                    changed_error_codes += 1;
                }
            }
            (Some(base_event), None) => {
                changed_events += 1;
                if diverged_at_sequence.is_none() {
                    diverged_at_sequence = Some(idx as u64);
                }
                if divergence_samples.len() < MAX_DIVERGENCE_SAMPLES {
                    divergence_samples.push(CounterfactualDivergenceSample {
                        sequence: idx as u64,
                        kind: CounterfactualDivergenceKind::MissingCounterfactualEvent,
                        baseline_component: Some(base_event.component.clone()),
                        counterfactual_component: None,
                        baseline_event: Some(base_event.event.clone()),
                        counterfactual_event: None,
                        baseline_outcome: Some(base_event.outcome.clone()),
                        counterfactual_outcome: None,
                        baseline_error_code: base_event.error_code.clone(),
                        counterfactual_error_code: None,
                    });
                }
            }
            (None, Some(alt_event)) => {
                changed_events += 1;
                if diverged_at_sequence.is_none() {
                    diverged_at_sequence = Some(idx as u64);
                }
                if divergence_samples.len() < MAX_DIVERGENCE_SAMPLES {
                    divergence_samples.push(CounterfactualDivergenceSample {
                        sequence: idx as u64,
                        kind: CounterfactualDivergenceKind::MissingBaselineEvent,
                        baseline_component: None,
                        counterfactual_component: Some(alt_event.component.clone()),
                        baseline_event: None,
                        counterfactual_event: Some(alt_event.event.clone()),
                        baseline_outcome: None,
                        counterfactual_outcome: Some(alt_event.outcome.clone()),
                        baseline_error_code: None,
                        counterfactual_error_code: alt_event.error_code.clone(),
                    });
                }
            }
            (None, None) => {}
        }
    }

    CounterfactualDelta {
        baseline_run_id: baseline.run_id.clone(),
        counterfactual_run_id: counterfactual.run_id.clone(),
        digest_changed: baseline.output_digest != counterfactual.output_digest,
        diverged_at_sequence,
        changed_events,
        changed_outcomes,
        changed_error_codes,
        baseline_event_count: baseline.events.len(),
        counterfactual_event_count: counterfactual.events.len(),
        transcript_changed: transcript_diverged_at_index.is_some(),
        transcript_diverged_at_index,
        divergence_samples,
    }
}

/// Persisted golden digest for a fixture.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GoldenBaseline {
    pub fixture_id: String,
    pub output_digest: String,
    pub source_run_id: String,
}

/// Signed artifact documenting an intentional golden update.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SignedGoldenUpdate {
    pub update_id: String,
    pub fixture_id: String,
    pub previous_digest: String,
    pub next_digest: String,
    pub source_run_id: String,
    pub signer: String,
    pub signature: String,
    pub rationale: String,
}

/// Golden verification failures.
#[derive(Debug)]
pub enum GoldenVerificationError {
    MissingBaseline { fixture_id: String },
    InvalidBaseline(io::Error),
    DigestMismatch { expected: String, actual: String },
}

impl fmt::Display for GoldenVerificationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::MissingBaseline { fixture_id } => {
                write!(f, "missing golden baseline for fixture `{fixture_id}`")
            }
            Self::InvalidBaseline(err) => write!(f, "invalid golden baseline: {err}"),
            Self::DigestMismatch { expected, actual } => {
                write!(
                    f,
                    "golden digest mismatch: expected `{expected}`, got `{actual}`"
                )
            }
        }
    }
}

impl Error for GoldenVerificationError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::InvalidBaseline(err) => Some(err),
            _ => None,
        }
    }
}

/// Content-addressed golden output store with signed update artifacts.
#[derive(Debug, Clone)]
pub struct GoldenStore {
    root: PathBuf,
}

impl GoldenStore {
    pub fn new(root: impl Into<PathBuf>) -> io::Result<Self> {
        let root = root.into();
        fs::create_dir_all(root.join("baselines"))?;
        fs::create_dir_all(root.join("updates"))?;
        Ok(Self { root })
    }

    pub fn write_baseline(&self, result: &RunResult) -> io::Result<PathBuf> {
        let baseline = GoldenBaseline {
            fixture_id: result.fixture_id.clone(),
            output_digest: result.output_digest.clone(),
            source_run_id: result.run_id.clone(),
        };
        let path = self.baseline_path(&result.fixture_id);
        write_atomic(&path, &canonical_json_bytes(&baseline)?)?;
        Ok(path)
    }

    pub fn verify_run(&self, result: &RunResult) -> Result<(), GoldenVerificationError> {
        let path = self.baseline_path(&result.fixture_id);
        if !path.exists() {
            return Err(GoldenVerificationError::MissingBaseline {
                fixture_id: result.fixture_id.clone(),
            });
        }

        let bytes = fs::read(path).map_err(GoldenVerificationError::InvalidBaseline)?;
        let baseline: GoldenBaseline = serde_json::from_slice(&bytes).map_err(|err| {
            GoldenVerificationError::InvalidBaseline(io::Error::new(
                io::ErrorKind::InvalidData,
                err,
            ))
        })?;

        if baseline.output_digest != result.output_digest {
            return Err(GoldenVerificationError::DigestMismatch {
                expected: baseline.output_digest,
                actual: result.output_digest.clone(),
            });
        }
        Ok(())
    }

    pub fn write_signed_update(
        &self,
        result: &RunResult,
        signer: &str,
        signature: &str,
        rationale: &str,
    ) -> io::Result<PathBuf> {
        if signer.trim().is_empty() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "signer is required",
            ));
        }
        if signature.trim().is_empty() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "signature is required",
            ));
        }
        if rationale.trim().is_empty() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "rationale is required",
            ));
        }

        let baseline = self.load_baseline(&result.fixture_id)?;
        let update_id = digest_hex(
            format!(
                "{}:{}:{}:{}:{}:{}",
                result.fixture_id,
                baseline.output_digest,
                result.output_digest,
                signer.trim(),
                signature.trim(),
                rationale.trim()
            )
            .as_bytes(),
        );

        let update = SignedGoldenUpdate {
            update_id: update_id.clone(),
            fixture_id: result.fixture_id.clone(),
            previous_digest: baseline.output_digest,
            next_digest: result.output_digest.clone(),
            source_run_id: result.run_id.clone(),
            signer: signer.trim().to_string(),
            signature: signature.trim().to_string(),
            rationale: rationale.trim().to_string(),
        };

        let path = self.root.join("updates").join(format!(
            "{}-{update_id}.json",
            sanitize_label(&result.fixture_id)
        ));
        write_atomic(&path, &canonical_json_bytes(&update)?)?;
        Ok(path)
    }

    fn load_baseline(&self, fixture_id: &str) -> io::Result<GoldenBaseline> {
        let path = self.baseline_path(fixture_id);
        let bytes = fs::read(path)?;
        serde_json::from_slice(&bytes)
            .map_err(|err| io::Error::new(io::ErrorKind::InvalidData, err))
    }

    fn baseline_path(&self, fixture_id: &str) -> PathBuf {
        self.root
            .join("baselines")
            .join(format!("{}.json", sanitize_label(fixture_id)))
    }
}

/// Machine-readable run manifest.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RunManifest {
    pub fixture_id: String,
    pub run_id: String,
    pub seed: u64,
    pub event_count: usize,
    pub output_digest: String,
    pub replay_pointer: String,
    pub model_snapshot_pointer: String,
    pub artifact_schema_version: u32,
    pub environment_fingerprint: ReplayEnvironmentFingerprint,
}

/// Human/machine report summary.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RunReport {
    pub fixture_id: String,
    pub run_id: String,
    pub pass: bool,
    pub event_count: usize,
    pub output_digest: String,
    pub first_error_code: Option<String>,
}

impl RunReport {
    pub fn from_result(result: &RunResult) -> Self {
        let first_error_code = result
            .events
            .iter()
            .find_map(|event| event.error_code.clone());
        // A run passes only when there are no error codes AND no events
        // with an error/failure outcome.
        let has_error_outcome = result
            .events
            .iter()
            .any(|event| event.outcome == "error" || event.outcome == "failure");
        Self {
            fixture_id: result.fixture_id.clone(),
            run_id: result.run_id.clone(),
            pass: first_error_code.is_none() && !has_error_outcome,
            event_count: result.events.len(),
            output_digest: result.output_digest.clone(),
            first_error_code,
        }
    }

    pub fn to_markdown(&self) -> String {
        let status = if self.pass { "pass" } else { "fail" };
        let first_error = self.first_error_code.as_deref().unwrap_or("none");
        format!(
            "# E2E Run Report\n\n- fixture_id: `{}`\n- run_id: `{}`\n- status: `{}`\n- event_count: `{}`\n- output_digest: `{}`\n- first_error_code: `{}`\n",
            self.fixture_id, self.run_id, status, self.event_count, self.output_digest, first_error
        )
    }
}

/// Paths to collected run artifacts.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CollectedArtifacts {
    pub manifest_path: PathBuf,
    pub events_path: PathBuf,
    pub evidence_linkage_path: PathBuf,
    pub report_json_path: PathBuf,
    pub report_markdown_path: PathBuf,
}

/// Collects deterministic artifacts for a test run.
#[derive(Debug, Clone)]
pub struct ArtifactCollector {
    root: PathBuf,
}

impl ArtifactCollector {
    pub fn new(root: impl Into<PathBuf>) -> io::Result<Self> {
        let root = root.into();
        fs::create_dir_all(&root)?;
        Ok(Self { root })
    }

    pub fn root(&self) -> &Path {
        &self.root
    }

    pub fn collect(&self, result: &RunResult) -> io::Result<CollectedArtifacts> {
        let run_root = self.root.join(&result.run_id);
        fs::create_dir_all(&run_root)?;

        let manifest = RunManifest {
            fixture_id: result.fixture_id.clone(),
            run_id: result.run_id.clone(),
            seed: result.seed,
            event_count: result.events.len(),
            output_digest: result.output_digest.clone(),
            replay_pointer: format!("replay://{}", result.run_id),
            model_snapshot_pointer: format!(
                "model://snapshot/{}/seed/{}",
                result.fixture_id, result.seed
            ),
            artifact_schema_version: 1,
            environment_fingerprint: ReplayEnvironmentFingerprint::local(),
        };
        let report = RunReport::from_result(result);
        let linkage = build_evidence_linkage(&result.events);

        let manifest_path = run_root.join("manifest.json");
        let events_path = run_root.join("events.jsonl");
        let evidence_linkage_path = run_root.join("evidence_linkage.json");
        let report_json_path = run_root.join("report.json");
        let report_markdown_path = run_root.join("report.md");

        write_atomic(&manifest_path, &canonical_json_bytes(&manifest)?)?;

        let mut jsonl = String::new();
        for event in &result.events {
            let line = serde_json::to_string(event)
                .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
            jsonl.push_str(&line);
            jsonl.push('\n');
        }
        write_atomic(&events_path, jsonl.as_bytes())?;
        write_atomic(&evidence_linkage_path, &canonical_json_bytes(&linkage)?)?;

        write_atomic(&report_json_path, &canonical_json_bytes(&report)?)?;
        write_atomic(&report_markdown_path, report.to_markdown().as_bytes())?;

        Ok(CollectedArtifacts {
            manifest_path,
            events_path,
            evidence_linkage_path,
            report_json_path,
            report_markdown_path,
        })
    }
}

/// Artifact completeness result for replay bundles.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ArtifactCompletenessReport {
    pub complete: bool,
    pub missing_files: Vec<String>,
    pub diagnostics: Vec<String>,
    pub event_count: usize,
    pub linkage_count: usize,
}

/// Audits replay artifacts for minimal external-verifier completeness.
pub fn audit_collected_artifacts(artifacts: &CollectedArtifacts) -> ArtifactCompletenessReport {
    let mut missing_files = Vec::new();
    let mut diagnostics = Vec::new();

    let required = [
        ("manifest", &artifacts.manifest_path),
        ("events", &artifacts.events_path),
        ("evidence_linkage", &artifacts.evidence_linkage_path),
        ("report_json", &artifacts.report_json_path),
        ("report_markdown", &artifacts.report_markdown_path),
    ];
    for (name, path) in required {
        if !path.exists() {
            missing_files.push(name.to_string());
        }
    }

    let mut event_count = 0usize;
    let mut linkage_count = 0usize;

    if missing_files.is_empty() {
        let manifest: Option<RunManifest> = match fs::read_to_string(&artifacts.manifest_path) {
            Ok(raw) => match serde_json::from_str(&raw) {
                Ok(value) => Some(value),
                Err(err) => {
                    diagnostics.push(format!("manifest parse error: {err}"));
                    None
                }
            },
            Err(err) => {
                diagnostics.push(format!("manifest read error: {err}"));
                None
            }
        };

        let report: Option<RunReport> = match fs::read_to_string(&artifacts.report_json_path) {
            Ok(raw) => match serde_json::from_str(&raw) {
                Ok(value) => Some(value),
                Err(err) => {
                    diagnostics.push(format!("report parse error: {err}"));
                    None
                }
            },
            Err(err) => {
                diagnostics.push(format!("report read error: {err}"));
                None
            }
        };

        let events: Option<Vec<HarnessEvent>> = match fs::read_to_string(&artifacts.events_path) {
            Ok(raw) => {
                let mut parsed = Vec::new();
                for (line_idx, line) in raw.lines().enumerate() {
                    if line.trim().is_empty() {
                        continue;
                    }
                    match serde_json::from_str::<HarnessEvent>(line) {
                        Ok(event) => parsed.push(event),
                        Err(err) => {
                            diagnostics
                                .push(format!("events line {} parse error: {err}", line_idx + 1));
                            return ArtifactCompletenessReport {
                                complete: false,
                                missing_files,
                                diagnostics,
                                event_count,
                                linkage_count,
                            };
                        }
                    }
                }
                Some(parsed)
            }
            Err(err) => {
                diagnostics.push(format!("events read error: {err}"));
                None
            }
        };

        let linkage: Option<Vec<EvidenceLinkageRecord>> =
            match fs::read_to_string(&artifacts.evidence_linkage_path) {
                Ok(raw) => match serde_json::from_str(&raw) {
                    Ok(value) => Some(value),
                    Err(err) => {
                        diagnostics.push(format!("evidence_linkage parse error: {err}"));
                        None
                    }
                },
                Err(err) => {
                    diagnostics.push(format!("evidence_linkage read error: {err}"));
                    None
                }
            };

        if let (Some(manifest), Some(report), Some(events), Some(linkage)) =
            (manifest, report, events, linkage)
        {
            event_count = events.len();
            linkage_count = linkage.len();

            if !manifest.replay_pointer.starts_with("replay://") {
                diagnostics.push("manifest replay_pointer missing replay:// prefix".to_string());
            }
            if !manifest.model_snapshot_pointer.starts_with("model://") {
                diagnostics
                    .push("manifest model_snapshot_pointer missing model:// prefix".to_string());
            }
            if manifest.artifact_schema_version == 0 {
                diagnostics.push("manifest artifact_schema_version must be non-zero".to_string());
            }
            if manifest.event_count != event_count {
                diagnostics.push(format!(
                    "manifest event_count mismatch: expected {}, got {}",
                    manifest.event_count, event_count
                ));
            }
            if report.event_count != event_count {
                diagnostics.push(format!(
                    "report event_count mismatch: expected {}, got {}",
                    report.event_count, event_count
                ));
            }
            if linkage_count != event_count {
                diagnostics.push(format!(
                    "evidence linkage count mismatch: expected {}, got {}",
                    event_count, linkage_count
                ));
            }
            if linkage
                .iter()
                .any(|row| row.evidence_hash.trim().is_empty())
            {
                diagnostics.push("evidence linkage contains empty evidence_hash".to_string());
            }
        }
    }

    ArtifactCompletenessReport {
        complete: missing_files.is_empty() && diagnostics.is_empty(),
        missing_files,
        diagnostics,
        event_count,
        linkage_count,
    }
}

/// Scenario class for expanded deterministic matrix execution.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ScenarioClass {
    Baseline,
    Differential,
    Chaos,
    Stress,
    FaultInjection,
    CrossArch,
}

impl ScenarioClass {
    pub const ALL: [Self; 6] = [
        Self::Baseline,
        Self::Differential,
        Self::Chaos,
        Self::Stress,
        Self::FaultInjection,
        Self::CrossArch,
    ];

    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Baseline => "baseline",
            Self::Differential => "differential",
            Self::Chaos => "chaos",
            Self::Stress => "stress",
            Self::FaultInjection => "fault_injection",
            Self::CrossArch => "cross_arch",
        }
    }
}

/// Schema version for the advanced RGC E2E scenario-matrix registry.
pub const RGC_ADVANCED_E2E_SCENARIO_SCHEMA_VERSION: &str =
    "franken-engine.rgc-advanced-e2e-scenario-matrix.v1";

const RGC_ADVANCED_BASELINE_SCENARIO_ID: &str = "rgc-053-runtime-baseline-01";

fn rgc_advanced_step(
    component: &str,
    event: &str,
    advance_micros: u64,
    domain: &str,
    journey: &str,
    error_code: Option<&str>,
) -> ScenarioStep {
    let mut metadata = BTreeMap::new();
    metadata.insert("domain".to_string(), domain.to_string());
    metadata.insert("journey".to_string(), journey.to_string());
    metadata.insert(
        "scenario_schema_version".to_string(),
        RGC_ADVANCED_E2E_SCENARIO_SCHEMA_VERSION.to_string(),
    );
    metadata.insert("scenario_class_hint".to_string(), journey.to_string());
    if let Some(error_code) = error_code {
        metadata.insert("error_code".to_string(), error_code.to_string());
    }
    ScenarioStep {
        component: component.to_string(),
        event: event.to_string(),
        advance_micros,
        metadata,
    }
}

fn rgc_advanced_fixture(
    fixture_id: &str,
    seed: u64,
    policy_id: &str,
    steps: Vec<ScenarioStep>,
) -> TestFixture {
    TestFixture {
        fixture_id: fixture_id.to_string(),
        fixture_version: TestFixture::CURRENT_VERSION,
        seed,
        virtual_time_start_micros: 2_000_000,
        policy_id: policy_id.to_string(),
        steps,
        expected_events: Vec::new(),
        determinism_check: true,
    }
}

fn rgc_advanced_stress_fixture() -> TestFixture {
    let mut steps = Vec::with_capacity(20);
    for idx in 0..20_u64 {
        steps.push(rgc_advanced_step(
            "scheduler",
            &format!("stress_tick_{idx}"),
            8 + idx,
            "runtime",
            "stress",
            None,
        ));
    }
    rgc_advanced_fixture(
        "rgc-053-runtime-stress-fixture",
        431,
        "policy-rgc-053-stress",
        steps,
    )
}

/// Canonical advanced scenario matrix for RGC-053 user-journey validation.
///
/// Coverage includes baseline, differential, chaos, stress, fault-injection,
/// and cross-arch classes with deterministic fixture seeds and unit anchors.
pub fn rgc_advanced_scenario_matrix_registry() -> Vec<ScenarioMatrixEntry> {
    let mut scenarios = vec![
        ScenarioMatrixEntry {
            scenario_id: RGC_ADVANCED_BASELINE_SCENARIO_ID.to_string(),
            scenario_class: ScenarioClass::Baseline,
            fixture: rgc_advanced_fixture(
                "rgc-053-runtime-baseline-fixture",
                401,
                "policy-rgc-053-runtime",
                vec![
                    rgc_advanced_step(
                        "router",
                        "ingest_runtime_request",
                        20,
                        "runtime",
                        "baseline",
                        None,
                    ),
                    rgc_advanced_step(
                        "scheduler",
                        "dispatch_runtime_lane",
                        30,
                        "runtime",
                        "baseline",
                        None,
                    ),
                    rgc_advanced_step(
                        "runtime_lane",
                        "execute_runtime_bundle",
                        40,
                        "runtime",
                        "baseline",
                        None,
                    ),
                ],
            ),
            baseline_scenario_id: None,
            chaos_profile: None,
            unit_anchor_ids: vec![
                "unit.e2e_harness.rgc_advanced_runtime_baseline".to_string(),
                "unit.e2e_harness.rgc_advanced_trace_contract".to_string(),
            ],
            target_arch: None,
            worker_pool: Some("pool-rgc-053-baseline".to_string()),
        },
        ScenarioMatrixEntry {
            scenario_id: "rgc-053-module-differential-01".to_string(),
            scenario_class: ScenarioClass::Differential,
            fixture: rgc_advanced_fixture(
                "rgc-053-module-differential-fixture",
                411,
                "policy-rgc-053-module",
                vec![
                    rgc_advanced_step(
                        "module_loader",
                        "resolve_entrypoint",
                        18,
                        "module",
                        "differential",
                        None,
                    ),
                    rgc_advanced_step(
                        "module_loader",
                        "link_dependency_graph",
                        27,
                        "module",
                        "differential",
                        None,
                    ),
                    rgc_advanced_step(
                        "runtime_lane",
                        "execute_linked_module",
                        33,
                        "module",
                        "differential",
                        None,
                    ),
                ],
            ),
            baseline_scenario_id: Some(RGC_ADVANCED_BASELINE_SCENARIO_ID.to_string()),
            chaos_profile: None,
            unit_anchor_ids: vec![
                "unit.e2e_harness.rgc_advanced_module_diff_alignment".to_string(),
            ],
            target_arch: None,
            worker_pool: Some("pool-rgc-053-differential".to_string()),
        },
        ScenarioMatrixEntry {
            scenario_id: "rgc-053-security-chaos-01".to_string(),
            scenario_class: ScenarioClass::Chaos,
            fixture: rgc_advanced_fixture(
                "rgc-053-security-chaos-fixture",
                421,
                "policy-rgc-053-security",
                vec![
                    rgc_advanced_step(
                        "security_guardplane",
                        "detect_risk_spike",
                        14,
                        "security",
                        "chaos",
                        None,
                    ),
                    rgc_advanced_step(
                        "security_guardplane",
                        "issue_challenge",
                        19,
                        "security",
                        "chaos",
                        None,
                    ),
                    rgc_advanced_step(
                        "containment_executor",
                        "sandbox_enforced",
                        26,
                        "security",
                        "chaos",
                        None,
                    ),
                ],
            ),
            baseline_scenario_id: None,
            chaos_profile: Some("latency_spike_partial_failure".to_string()),
            unit_anchor_ids: vec![
                "unit.e2e_harness.rgc_advanced_security_chaos_profile".to_string(),
            ],
            target_arch: None,
            worker_pool: Some("pool-rgc-053-chaos".to_string()),
        },
        ScenarioMatrixEntry {
            scenario_id: "rgc-053-runtime-stress-01".to_string(),
            scenario_class: ScenarioClass::Stress,
            fixture: rgc_advanced_stress_fixture(),
            baseline_scenario_id: None,
            chaos_profile: None,
            unit_anchor_ids: vec![
                "unit.e2e_harness.rgc_advanced_runtime_stress_budget".to_string(),
            ],
            target_arch: None,
            worker_pool: Some("pool-rgc-053-stress".to_string()),
        },
        ScenarioMatrixEntry {
            scenario_id: "rgc-053-security-fault-01".to_string(),
            scenario_class: ScenarioClass::FaultInjection,
            fixture: rgc_advanced_fixture(
                "rgc-053-security-fault-fixture",
                429,
                "policy-rgc-053-security-fault",
                vec![
                    rgc_advanced_step(
                        "security_guardplane",
                        "risk_threshold_exceeded",
                        15,
                        "security",
                        "fault_injection",
                        Some("FE-RGC-053-SECURITY-FAULT-0001"),
                    ),
                    rgc_advanced_step(
                        "containment_executor",
                        "quarantine_applied",
                        24,
                        "security",
                        "fault_injection",
                        None,
                    ),
                ],
            ),
            baseline_scenario_id: None,
            chaos_profile: None,
            unit_anchor_ids: vec![
                "unit.e2e_harness.rgc_advanced_security_fault_contract".to_string(),
            ],
            target_arch: None,
            worker_pool: Some("pool-rgc-053-fault".to_string()),
        },
        ScenarioMatrixEntry {
            scenario_id: "rgc-053-runtime-cross-arch-01".to_string(),
            scenario_class: ScenarioClass::CrossArch,
            fixture: rgc_advanced_fixture(
                "rgc-053-cross-arch-fixture",
                433,
                "policy-rgc-053-cross-arch",
                vec![
                    rgc_advanced_step(
                        "parser_frontend",
                        "parse_program",
                        16,
                        "runtime",
                        "cross_arch",
                        None,
                    ),
                    rgc_advanced_step(
                        "lowering_pipeline",
                        "lower_ir0_to_ir3",
                        21,
                        "runtime",
                        "cross_arch",
                        None,
                    ),
                    rgc_advanced_step(
                        "runtime_lane",
                        "execute_cross_arch_bundle",
                        25,
                        "runtime",
                        "cross_arch",
                        None,
                    ),
                ],
            ),
            baseline_scenario_id: None,
            chaos_profile: None,
            unit_anchor_ids: vec![
                "unit.e2e_harness.rgc_advanced_cross_arch_replay_contract".to_string(),
            ],
            target_arch: Some("aarch64-unknown-linux-gnu".to_string()),
            worker_pool: Some("pool-rgc-053-cross-arch".to_string()),
        },
    ];

    scenarios.sort_by(|left, right| left.scenario_id.cmp(&right.scenario_id));
    scenarios
}

/// Selects scenarios from [`rgc_advanced_scenario_matrix_registry`] with
/// deterministic ordering and optional fault-injection filtering.
pub fn select_rgc_advanced_scenario_matrix(
    classes: &[ScenarioClass],
    include_fault_injection: bool,
) -> Vec<ScenarioMatrixEntry> {
    let mut selected: Vec<_> = rgc_advanced_scenario_matrix_registry()
        .into_iter()
        .filter(|scenario| classes.is_empty() || classes.contains(&scenario.scenario_class))
        .filter(|scenario| {
            include_fault_injection || scenario.scenario_class != ScenarioClass::FaultInjection
        })
        .collect();
    selected.sort_by(|left, right| left.scenario_id.cmp(&right.scenario_id));
    selected
}

/// One matrix scenario entry.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ScenarioMatrixEntry {
    pub scenario_id: String,
    pub scenario_class: ScenarioClass,
    pub fixture: TestFixture,
    #[serde(default)]
    pub baseline_scenario_id: Option<String>,
    #[serde(default)]
    pub chaos_profile: Option<String>,
    #[serde(default)]
    pub unit_anchor_ids: Vec<String>,
    #[serde(default)]
    pub target_arch: Option<String>,
    #[serde(default)]
    pub worker_pool: Option<String>,
}

/// Relative artifact paths for one scenario evidence pack.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ScenarioArtifactPaths {
    pub manifest: String,
    pub events: String,
    pub evidence_linkage: String,
    pub report_json: String,
    pub report_markdown: String,
}

/// Evidence pack for one scenario execution.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ScenarioEvidencePack {
    pub scenario_id: String,
    pub scenario_class: ScenarioClass,
    pub baseline_scenario_id: Option<String>,
    pub chaos_profile: Option<String>,
    pub unit_anchor_ids: Vec<String>,
    pub target_arch: Option<String>,
    pub worker_pool: Option<String>,
    pub fixture_id: String,
    pub run_id: String,
    pub output_digest: String,
    pub event_count: usize,
    pub pass: bool,
    pub first_error_code: Option<String>,
    pub replay_pointer: String,
    pub artifact_paths: ScenarioArtifactPaths,
    pub completeness: ArtifactCompletenessReport,
}

/// Aggregated report for a scenario matrix run.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ScenarioMatrixReport {
    pub schema_version: String,
    pub summary_id: String,
    pub total_scenarios: u64,
    pub pass_scenarios: u64,
    pub fail_scenarios: u64,
    pub scenario_packs: Vec<ScenarioEvidencePack>,
}

/// Concrete summary outputs for a scenario matrix run.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ScenarioMatrixExecution {
    pub report: ScenarioMatrixReport,
    pub summary_json_path: PathBuf,
    pub summary_markdown_path: PathBuf,
}

/// Runs a deterministic scenario matrix and writes a summary evidence pack.
pub fn run_scenario_matrix(
    runner: &DeterministicRunner,
    collector: &ArtifactCollector,
    scenarios: &[ScenarioMatrixEntry],
) -> io::Result<ScenarioMatrixExecution> {
    if scenarios.is_empty() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "scenario matrix requires at least one scenario",
        ));
    }

    let mut packs = Vec::with_capacity(scenarios.len());
    for scenario in scenarios {
        if scenario.scenario_id.trim().is_empty() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "scenario_id is required",
            ));
        }
        if scenario.unit_anchor_ids.is_empty() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!(
                    "scenario {} requires at least one unit_anchor_id",
                    scenario.scenario_id
                ),
            ));
        }

        match scenario.scenario_class {
            ScenarioClass::Differential => {
                let missing_baseline = scenario
                    .baseline_scenario_id
                    .as_ref()
                    .map(|value| value.trim().is_empty())
                    .unwrap_or(true);
                if missing_baseline {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidInput,
                        format!(
                            "scenario {} (differential) requires baseline_scenario_id",
                            scenario.scenario_id
                        ),
                    ));
                }
            }
            ScenarioClass::Chaos => {
                let missing_profile = scenario
                    .chaos_profile
                    .as_ref()
                    .map(|value| value.trim().is_empty())
                    .unwrap_or(true);
                if missing_profile {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidInput,
                        format!(
                            "scenario {} (chaos) requires chaos_profile",
                            scenario.scenario_id
                        ),
                    ));
                }
            }
            _ => {}
        }

        let run = runner
            .run_fixture(&scenario.fixture)
            .map_err(|err| io::Error::new(io::ErrorKind::InvalidInput, err.to_string()))?;
        let artifacts = collector.collect(&run)?;
        let completeness = audit_collected_artifacts(&artifacts);
        let report = RunReport::from_result(&run);
        let pass = report.pass && completeness.complete;

        packs.push(ScenarioEvidencePack {
            scenario_id: scenario.scenario_id.clone(),
            scenario_class: scenario.scenario_class,
            baseline_scenario_id: scenario.baseline_scenario_id.clone(),
            chaos_profile: scenario.chaos_profile.clone(),
            unit_anchor_ids: scenario.unit_anchor_ids.clone(),
            target_arch: scenario.target_arch.clone(),
            worker_pool: scenario.worker_pool.clone(),
            fixture_id: run.fixture_id.clone(),
            run_id: run.run_id.clone(),
            output_digest: run.output_digest.clone(),
            event_count: run.events.len(),
            pass,
            first_error_code: report.first_error_code,
            replay_pointer: format!("replay://{}", run.run_id),
            artifact_paths: ScenarioArtifactPaths {
                manifest: path_relative_to(collector.root(), &artifacts.manifest_path),
                events: path_relative_to(collector.root(), &artifacts.events_path),
                evidence_linkage: path_relative_to(
                    collector.root(),
                    &artifacts.evidence_linkage_path,
                ),
                report_json: path_relative_to(collector.root(), &artifacts.report_json_path),
                report_markdown: path_relative_to(
                    collector.root(),
                    &artifacts.report_markdown_path,
                ),
            },
            completeness,
        });
    }

    let total_scenarios = packs.len() as u64;
    let pass_scenarios = packs.iter().filter(|pack| pack.pass).count() as u64;
    let fail_scenarios = total_scenarios.saturating_sub(pass_scenarios);
    let summary_id = scenario_matrix_summary_id(&packs);
    let report = ScenarioMatrixReport {
        schema_version: "franken-engine.e2e-scenario-matrix.report.v2".to_string(),
        summary_id,
        total_scenarios,
        pass_scenarios,
        fail_scenarios,
        scenario_packs: packs,
    };

    let summary_json_path = collector.root().join("scenario_matrix_summary.json");
    let summary_markdown_path = collector.root().join("scenario_matrix_summary.md");
    write_atomic(&summary_json_path, &canonical_json_bytes(&report)?)?;
    write_atomic(
        &summary_markdown_path,
        scenario_matrix_summary_markdown(&report).as_bytes(),
    )?;

    Ok(ScenarioMatrixExecution {
        report,
        summary_json_path,
        summary_markdown_path,
    })
}

fn scenario_matrix_summary_id(packs: &[ScenarioEvidencePack]) -> String {
    let mut preimage = String::new();
    for pack in packs {
        let anchors = if pack.unit_anchor_ids.is_empty() {
            "-".to_string()
        } else {
            pack.unit_anchor_ids.join(",")
        };
        let line = format!(
            "{}:{}:{}:{}:{}:{}:{}:{};",
            pack.scenario_id,
            pack.run_id,
            pack.output_digest,
            pack.pass,
            pack.replay_pointer,
            pack.baseline_scenario_id.as_deref().unwrap_or("-"),
            pack.chaos_profile.as_deref().unwrap_or("-"),
            anchors
        );
        preimage.push_str(&line);
    }
    digest_hex(preimage.as_bytes())
}

fn scenario_matrix_summary_markdown(report: &ScenarioMatrixReport) -> String {
    let mut markdown = String::from(
        "# E2E Scenario Matrix Summary\n\n| scenario_id | class | pass | run_id | output_digest | baseline | chaos_profile | unit_anchors |\n|---|---|---:|---|---|---|---|---|\n",
    );
    for pack in &report.scenario_packs {
        let anchors = if pack.unit_anchor_ids.is_empty() {
            "-".to_string()
        } else {
            pack.unit_anchor_ids.join(",")
        };
        markdown.push_str(&format!(
            "| {} | {:?} | {} | {} | {} | {} | {} | {} |\n",
            pack.scenario_id,
            pack.scenario_class,
            pack.pass,
            pack.run_id,
            pack.output_digest,
            pack.baseline_scenario_id.as_deref().unwrap_or("-"),
            pack.chaos_profile.as_deref().unwrap_or("-"),
            anchors
        ));
    }
    markdown.push_str(&format!(
        "\n- summary_id: `{}`\n- total_scenarios: `{}`\n- pass_scenarios: `{}`\n- fail_scenarios: `{}`\n",
        report.summary_id, report.total_scenarios, report.pass_scenarios, report.fail_scenarios
    ));
    markdown
}

fn path_relative_to(root: &Path, path: &Path) -> String {
    match path.strip_prefix(root) {
        Ok(relative) => relative.display().to_string(),
        Err(_) => path.display().to_string(),
    }
}

fn canonical_json_bytes<T: Serialize>(value: &T) -> io::Result<Vec<u8>> {
    serde_json::to_vec(value).map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))
}

fn digest_run(
    fixture_id: &str,
    seed: u64,
    random_transcript: &[u64],
    events: &[HarnessEvent],
) -> String {
    #[derive(Serialize)]
    struct DigestEnvelope<'a> {
        fixture_id: &'a str,
        seed: u64,
        random_transcript: &'a [u64],
        events: &'a [HarnessEvent],
    }

    match serde_json::to_vec(&DigestEnvelope {
        fixture_id,
        seed,
        random_transcript,
        events,
    }) {
        Ok(bytes) => digest_hex(&bytes),
        Err(e) => format!("digest-error-{:016x}", fnv1a64(e.to_string().as_bytes())),
    }
}

fn digest_hex(bytes: &[u8]) -> String {
    format!("{:016x}", fnv1a64(bytes))
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

fn sanitize_label(input: &str) -> String {
    let mut out = String::with_capacity(input.len());
    for c in input.chars() {
        if c.is_ascii_alphanumeric() || c == '-' || c == '_' {
            out.push(c);
        } else {
            out.push('-');
        }
    }
    out
}

fn write_atomic(path: &Path, bytes: &[u8]) -> io::Result<()> {
    let parent = path
        .parent()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "path has no parent"))?;
    fs::create_dir_all(parent)?;

    let mut tmp_name = path.file_name().unwrap_or_default().to_owned();
    tmp_name.push(".tmp");
    let tmp = parent.join(tmp_name);
    fs::write(&tmp, bytes)?;
    fs::rename(&tmp, path)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    // ── VirtualClock ──────────────────────────────────────────────

    #[test]
    fn virtual_clock_new_and_now() {
        let clock = VirtualClock::new(1000);
        assert_eq!(clock.now_micros(), 1000);
    }

    #[test]
    fn virtual_clock_advance() {
        let mut clock = VirtualClock::new(100);
        clock.advance(50);
        assert_eq!(clock.now_micros(), 150);
    }

    #[test]
    fn virtual_clock_advance_saturating() {
        let mut clock = VirtualClock::new(u64::MAX - 5);
        clock.advance(100);
        assert_eq!(clock.now_micros(), u64::MAX);
    }

    #[test]
    fn virtual_clock_serde_round_trip() {
        let clock = VirtualClock::new(42);
        let json = serde_json::to_string(&clock).unwrap();
        let back: VirtualClock = serde_json::from_str(&json).unwrap();
        assert_eq!(clock, back);
    }

    // ── DeterministicRng ──────────────────────────────────────────

    #[test]
    fn rng_seeded_deterministic() {
        let mut a = DeterministicRng::seeded(123);
        let mut b = DeterministicRng::seeded(123);
        let seq_a: Vec<u64> = (0..10).map(|_| a.next_u64()).collect();
        let seq_b: Vec<u64> = (0..10).map(|_| b.next_u64()).collect();
        assert_eq!(seq_a, seq_b);
    }

    #[test]
    fn rng_different_seeds_differ() {
        let mut a = DeterministicRng::seeded(1);
        let mut b = DeterministicRng::seeded(2);
        assert_ne!(a.next_u64(), b.next_u64());
    }

    #[test]
    fn rng_zero_seed_not_stuck() {
        let mut rng = DeterministicRng::seeded(0);
        let v1 = rng.next_u64();
        let v2 = rng.next_u64();
        assert_ne!(v1, 0);
        assert_ne!(v1, v2);
    }

    #[test]
    fn rng_serde_round_trip() {
        let rng = DeterministicRng::seeded(999);
        let json = serde_json::to_string(&rng).unwrap();
        let back: DeterministicRng = serde_json::from_str(&json).unwrap();
        assert_eq!(rng, back);
    }

    // ── ScenarioStep / ExpectedEvent serde ────────────────────────

    #[test]
    fn scenario_step_defaults() {
        let json = r#"{"component":"c","event":"e"}"#;
        let step: ScenarioStep = serde_json::from_str(json).unwrap();
        assert_eq!(step.advance_micros, 0);
        assert!(step.metadata.is_empty());
    }

    #[test]
    fn expected_event_round_trip() {
        let ev = ExpectedEvent {
            component: "comp".into(),
            event: "evt".into(),
            outcome: "ok".into(),
            error_code: Some("E001".into()),
        };
        let json = serde_json::to_string(&ev).unwrap();
        let back: ExpectedEvent = serde_json::from_str(&json).unwrap();
        assert_eq!(ev, back);
    }

    // ── TestFixture ───────────────────────────────────────────────

    fn valid_fixture() -> TestFixture {
        TestFixture {
            fixture_id: "fix-001".into(),
            fixture_version: TestFixture::CURRENT_VERSION,
            seed: 42,
            virtual_time_start_micros: 1000,
            policy_id: "policy-A".into(),
            steps: vec![ScenarioStep {
                component: "auth".into(),
                event: "login".into(),
                advance_micros: 100,
                metadata: BTreeMap::new(),
            }],
            expected_events: vec![],
            determinism_check: false,
        }
    }

    #[test]
    fn fixture_validate_valid() {
        assert!(valid_fixture().validate().is_ok());
    }

    #[test]
    fn fixture_validate_missing_fixture_id() {
        let mut f = valid_fixture();
        f.fixture_id = "  ".into();
        assert!(matches!(
            f.validate(),
            Err(FixtureValidationError::MissingFixtureId)
        ));
    }

    #[test]
    fn fixture_validate_wrong_version() {
        let mut f = valid_fixture();
        f.fixture_version = 99;
        assert!(matches!(
            f.validate(),
            Err(FixtureValidationError::UnsupportedVersion { .. })
        ));
    }

    #[test]
    fn fixture_validate_missing_policy_id() {
        let mut f = valid_fixture();
        f.policy_id = "".into();
        assert!(matches!(
            f.validate(),
            Err(FixtureValidationError::MissingPolicyId)
        ));
    }

    #[test]
    fn fixture_validate_missing_steps() {
        let mut f = valid_fixture();
        f.steps.clear();
        assert!(matches!(
            f.validate(),
            Err(FixtureValidationError::MissingSteps)
        ));
    }

    #[test]
    fn fixture_validate_empty_component() {
        let mut f = valid_fixture();
        f.steps[0].component = "".into();
        assert!(matches!(
            f.validate(),
            Err(FixtureValidationError::InvalidStep { index: 0, .. })
        ));
    }

    #[test]
    fn fixture_validate_empty_event() {
        let mut f = valid_fixture();
        f.steps[0].event = " ".into();
        assert!(matches!(
            f.validate(),
            Err(FixtureValidationError::InvalidStep { index: 0, .. })
        ));
    }

    #[test]
    fn fixture_serde_round_trip() {
        let f = valid_fixture();
        let json = serde_json::to_string(&f).unwrap();
        let back: TestFixture = serde_json::from_str(&json).unwrap();
        assert_eq!(f, back);
    }

    #[test]
    fn parse_fixture_with_migration_supports_legacy_v0() {
        let legacy = serde_json::json!({
            "fixture_id": "legacy-fix",
            "fixture_version": 0,
            "seed": 7,
            "virtual_time_start_micros": 123,
            "policy_id": "policy-legacy",
            "steps": [
                {
                    "component": "scheduler",
                    "event": "dispatch",
                    "advance_micros": 5
                }
            ]
        });
        let bytes = serde_json::to_vec(&legacy).unwrap();
        let migrated = parse_fixture_with_migration(&bytes).unwrap();
        assert_eq!(migrated.fixture_version, TestFixture::CURRENT_VERSION);
        assert_eq!(migrated.fixture_id, "legacy-fix");
        assert!(migrated.expected_events.is_empty());
        assert!(migrated.determinism_check);
    }

    #[test]
    fn parse_fixture_with_migration_rejects_unknown_version() {
        let payload = serde_json::json!({
            "fixture_id": "future-fix",
            "fixture_version": 99,
            "seed": 1,
            "virtual_time_start_micros": 0,
            "policy_id": "policy",
            "steps": [{"component":"c","event":"e"}]
        });
        let bytes = serde_json::to_vec(&payload).unwrap();
        let err = parse_fixture_with_migration(&bytes).unwrap_err();
        assert!(matches!(
            err,
            FixtureMigrationError::UnsupportedVersion {
                expected: 1,
                actual: 99
            }
        ));
    }

    // ── FixtureValidationError Display ────────────────────────────

    #[test]
    fn fixture_error_display_missing_fixture_id() {
        let e = FixtureValidationError::MissingFixtureId;
        assert_eq!(e.to_string(), "fixture_id is required");
    }

    #[test]
    fn fixture_error_display_missing_policy_id() {
        let e = FixtureValidationError::MissingPolicyId;
        assert_eq!(e.to_string(), "policy_id is required");
    }

    #[test]
    fn fixture_error_display_missing_steps() {
        let e = FixtureValidationError::MissingSteps;
        assert_eq!(e.to_string(), "fixture must contain at least one step");
    }

    #[test]
    fn fixture_error_display_unsupported_version() {
        let e = FixtureValidationError::UnsupportedVersion {
            expected: 1,
            actual: 5,
        };
        assert!(e.to_string().contains("expected 1"));
        assert!(e.to_string().contains("got 5"));
    }

    #[test]
    fn fixture_error_display_invalid_step() {
        let e = FixtureValidationError::InvalidStep {
            index: 3,
            reason: "oops".into(),
        };
        assert!(e.to_string().contains("index 3"));
        assert!(e.to_string().contains("oops"));
    }

    // ── DeterministicRunner ───────────────────────────────────────

    #[test]
    fn runner_default_config() {
        let cfg = DeterministicRunnerConfig::default();
        assert_eq!(cfg.trace_prefix, "trace");
    }

    #[test]
    fn runner_run_fixture_basic() {
        let runner = DeterministicRunner::default();
        let fixture = valid_fixture();
        let result = runner.run_fixture(&fixture).unwrap();
        assert_eq!(result.fixture_id, "fix-001");
        assert_eq!(result.seed, 42);
        assert_eq!(result.events.len(), 1);
        assert_eq!(result.random_transcript.len(), 1);
        assert_eq!(result.start_virtual_time_micros, 1000);
        assert_eq!(result.end_virtual_time_micros, 1100);
    }

    #[test]
    fn runner_run_fixture_deterministic() {
        let runner = DeterministicRunner::default();
        let fixture = valid_fixture();
        let r1 = runner.run_fixture(&fixture).unwrap();
        let r2 = runner.run_fixture(&fixture).unwrap();
        assert_eq!(r1.output_digest, r2.output_digest);
        assert_eq!(r1.events, r2.events);
        assert_eq!(r1.random_transcript, r2.random_transcript);
    }

    #[test]
    fn runner_run_fixture_rejects_invalid() {
        let runner = DeterministicRunner::default();
        let mut f = valid_fixture();
        f.steps.clear();
        assert!(runner.run_fixture(&f).is_err());
    }

    #[test]
    fn runner_event_has_trace_prefix() {
        let runner = DeterministicRunner {
            config: DeterministicRunnerConfig {
                trace_prefix: "custom".into(),
            },
        };
        let result = runner.run_fixture(&valid_fixture()).unwrap();
        assert!(result.events[0].trace_id.starts_with("custom-"));
    }

    #[test]
    fn runner_error_code_propagation() {
        let mut f = valid_fixture();
        let mut meta = BTreeMap::new();
        meta.insert("error_code".into(), "E_TEST".into());
        f.steps[0].metadata = meta;
        let runner = DeterministicRunner::default();
        let result = runner.run_fixture(&f).unwrap();
        assert_eq!(result.events[0].outcome, "error");
        assert_eq!(result.events[0].error_code.as_deref(), Some("E_TEST"));
    }

    #[test]
    fn runner_custom_outcome() {
        let mut f = valid_fixture();
        let mut meta = BTreeMap::new();
        meta.insert("outcome".into(), "warn".into());
        f.steps[0].metadata = meta;
        let runner = DeterministicRunner::default();
        let result = runner.run_fixture(&f).unwrap();
        assert_eq!(result.events[0].outcome, "warn");
    }

    #[test]
    fn runner_multiple_steps_time_advances() {
        let mut f = valid_fixture();
        f.steps.push(ScenarioStep {
            component: "db".into(),
            event: "query".into(),
            advance_micros: 200,
            metadata: BTreeMap::new(),
        });
        let runner = DeterministicRunner::default();
        let result = runner.run_fixture(&f).unwrap();
        assert_eq!(result.events.len(), 2);
        assert_eq!(result.events[0].virtual_time_micros, 1100);
        assert_eq!(result.events[1].virtual_time_micros, 1300);
        assert_eq!(result.events[0].sequence, 0);
        assert_eq!(result.events[1].sequence, 1);
    }

    // ── assert_structured_logs ────────────────────────────────────

    #[test]
    fn assert_logs_all_match() {
        let events = vec![HarnessEvent {
            trace_id: "t".into(),
            decision_id: "d".into(),
            policy_id: "p".into(),
            component: "auth".into(),
            event: "login".into(),
            outcome: "ok".into(),
            error_code: None,
            sequence: 0,
            virtual_time_micros: 0,
        }];
        let expectations = vec![LogExpectation {
            component: "auth".into(),
            event: "login".into(),
            outcome: "ok".into(),
            error_code: None,
        }];
        assert!(assert_structured_logs(&events, &expectations).is_ok());
    }

    #[test]
    fn assert_logs_missing() {
        let events = vec![];
        let expectations = vec![LogExpectation {
            component: "auth".into(),
            event: "login".into(),
            outcome: "ok".into(),
            error_code: None,
        }];
        let err = assert_structured_logs(&events, &expectations).unwrap_err();
        assert_eq!(err.missing.len(), 1);
        assert!(err.to_string().contains("1"));
    }

    #[test]
    fn assert_logs_empty_expectations_pass() {
        let events = vec![HarnessEvent {
            trace_id: "t".into(),
            decision_id: "d".into(),
            policy_id: "p".into(),
            component: "c".into(),
            event: "e".into(),
            outcome: "ok".into(),
            error_code: None,
            sequence: 0,
            virtual_time_micros: 0,
        }];
        assert!(assert_structured_logs(&events, &[]).is_ok());
    }

    #[test]
    fn assert_logs_error_code_mismatch() {
        let events = vec![HarnessEvent {
            trace_id: "t".into(),
            decision_id: "d".into(),
            policy_id: "p".into(),
            component: "auth".into(),
            event: "login".into(),
            outcome: "ok".into(),
            error_code: None,
            sequence: 0,
            virtual_time_micros: 0,
        }];
        let expectations = vec![LogExpectation {
            component: "auth".into(),
            event: "login".into(),
            outcome: "ok".into(),
            error_code: Some("E001".into()),
        }];
        assert!(assert_structured_logs(&events, &expectations).is_err());
    }

    // ── verify_replay ─────────────────────────────────────────────

    fn make_run_result(digest: &str, seed: u64) -> RunResult {
        RunResult {
            fixture_id: "fix-1".into(),
            run_id: "run-1".into(),
            seed,
            start_virtual_time_micros: 0,
            end_virtual_time_micros: 100,
            random_transcript: vec![seed],
            events: vec![],
            output_digest: digest.into(),
        }
    }

    #[test]
    fn replay_matches() {
        let a = make_run_result("abc", 1);
        let b = make_run_result("abc", 1);
        let v = verify_replay(&a, &b);
        assert!(v.matches);
        assert!(v.reason.is_none());
        assert!(v.mismatch_kind.is_none());
        assert!(v.diverged_event_sequence.is_none());
        assert!(v.transcript_mismatch_index.is_none());
    }

    #[test]
    fn replay_digest_mismatch() {
        let a = make_run_result("abc", 1);
        let b = make_run_result("xyz", 1);
        let v = verify_replay(&a, &b);
        assert!(!v.matches);
        assert_eq!(v.reason.as_deref(), Some("digest mismatch"));
        assert_eq!(v.mismatch_kind, Some(ReplayMismatchKind::Digest));
    }

    #[test]
    fn replay_event_stream_mismatch() {
        let mut a = make_run_result("abc", 1);
        let mut b = make_run_result("abc", 1);
        a.events.push(HarnessEvent {
            trace_id: "t".into(),
            decision_id: "d".into(),
            policy_id: "p".into(),
            component: "scheduler".into(),
            event: "dispatch".into(),
            outcome: "ok".into(),
            error_code: None,
            sequence: 0,
            virtual_time_micros: 0,
        });
        b.events.push(HarnessEvent {
            trace_id: "t".into(),
            decision_id: "d".into(),
            policy_id: "p".into(),
            component: "scheduler".into(),
            event: "dispatch".into(),
            outcome: "error".into(),
            error_code: Some("FE-E2E-9999".into()),
            sequence: 0,
            virtual_time_micros: 0,
        });
        let v = verify_replay(&a, &b);
        assert!(!v.matches);
        assert_eq!(v.reason.as_deref(), Some("event stream mismatch"));
        assert_eq!(v.mismatch_kind, Some(ReplayMismatchKind::EventStream));
        assert_eq!(v.diverged_event_sequence, Some(0));
        assert!(v.transcript_mismatch_index.is_none());
    }

    #[test]
    fn replay_transcript_mismatch() {
        let a = make_run_result("abc", 1);
        let mut b = make_run_result("abc", 1);
        b.random_transcript = vec![999];
        let v = verify_replay(&a, &b);
        assert!(!v.matches);
        assert_eq!(v.reason.as_deref(), Some("random transcript mismatch"));
        assert_eq!(v.mismatch_kind, Some(ReplayMismatchKind::RandomTranscript));
        assert_eq!(v.transcript_mismatch_index, Some(0));
        assert_eq!(v.expected_transcript_len, 1);
        assert_eq!(v.actual_transcript_len, 1);
    }

    #[test]
    fn replay_performance_faster_than_realtime() {
        let run = make_run_result("abc", 1);
        let perf = evaluate_replay_performance(&run, 50);
        assert_eq!(perf.virtual_duration_micros, 100);
        assert_eq!(perf.wall_duration_micros, 50);
        assert!(perf.faster_than_realtime);
        assert_eq!(perf.speedup_milli, 2000);
    }

    #[test]
    fn replay_performance_slower_than_realtime() {
        let run = make_run_result("abc", 1);
        let perf = evaluate_replay_performance(&run, 250);
        assert_eq!(perf.virtual_duration_micros, 100);
        assert_eq!(perf.wall_duration_micros, 250);
        assert!(!perf.faster_than_realtime);
        assert_eq!(perf.speedup_milli, 400);
    }

    #[test]
    fn cross_machine_replay_diag_environment_delta_with_match() {
        let a = make_run_result("abc", 1);
        let b = make_run_result("abc", 1);
        let expected_env = ReplayEnvironmentFingerprint {
            os: "linux".into(),
            architecture: "x86_64".into(),
            family: "unix".into(),
            pointer_width_bits: 64,
            endian: "little".into(),
        };
        let actual_env = ReplayEnvironmentFingerprint {
            os: "linux".into(),
            architecture: "aarch64".into(),
            family: "unix".into(),
            pointer_width_bits: 64,
            endian: "little".into(),
        };
        let diag = diagnose_cross_machine_replay(&a, &b, &expected_env, &actual_env);
        assert!(diag.cross_machine_match);
        assert_eq!(
            diag.environment_mismatches,
            vec!["architecture".to_string()]
        );
        assert_eq!(
            diag.diagnosis.as_deref(),
            Some("replay matched across environment deltas: architecture")
        );
    }

    #[test]
    fn cross_machine_replay_diag_mismatch_includes_environment_context() {
        let a = make_run_result("abc", 1);
        let b = make_run_result("xyz", 1);
        let expected_env = ReplayEnvironmentFingerprint {
            os: "linux".into(),
            architecture: "x86_64".into(),
            family: "unix".into(),
            pointer_width_bits: 64,
            endian: "little".into(),
        };
        let actual_env = ReplayEnvironmentFingerprint {
            os: "windows".into(),
            architecture: "x86_64".into(),
            family: "windows".into(),
            pointer_width_bits: 64,
            endian: "little".into(),
        };
        let diag = diagnose_cross_machine_replay(&a, &b, &expected_env, &actual_env);
        assert!(!diag.cross_machine_match);
        assert_eq!(
            diag.environment_mismatches,
            vec!["os".to_string(), "family".to_string()]
        );
        assert_eq!(
            diag.diagnosis.as_deref(),
            Some("replay mismatch: digest mismatch; environment mismatch fields: os, family")
        );
    }

    #[test]
    fn replay_input_validation_rejects_missing_model_snapshot() {
        let run = make_run_result("abc", 1);
        let err = validate_replay_input(&run, None).unwrap_err();
        assert_eq!(err.code, ReplayInputErrorCode::MissingModelSnapshot);
    }

    #[test]
    fn replay_input_validation_rejects_partial_trace_gap() {
        let mut run = make_run_result("abc", 1);
        run.events = vec![
            HarnessEvent {
                trace_id: "trace-a".into(),
                decision_id: "decision-0000".into(),
                policy_id: "policy-a".into(),
                component: "scheduler".into(),
                event: "dispatch".into(),
                outcome: "ok".into(),
                error_code: None,
                sequence: 0,
                virtual_time_micros: 100,
            },
            HarnessEvent {
                trace_id: "trace-a".into(),
                decision_id: "decision-0001".into(),
                policy_id: "policy-a".into(),
                component: "scheduler".into(),
                event: "complete".into(),
                outcome: "ok".into(),
                error_code: None,
                sequence: 2,
                virtual_time_micros: 200,
            },
        ];
        run.random_transcript = vec![10, 20];
        run.output_digest = digest_run(
            &run.fixture_id,
            run.seed,
            &run.random_transcript,
            &run.events,
        );

        let err = validate_replay_input(&run, Some("model://snapshot/fix-1")).unwrap_err();
        assert_eq!(err.code, ReplayInputErrorCode::PartialTrace);
        assert!(err.message.contains("expected 1, got 2"));
    }

    #[test]
    fn replay_input_validation_rejects_corrupted_transcript_length() {
        let mut run = make_run_result("abc", 1);
        run.events = vec![HarnessEvent {
            trace_id: "trace-a".into(),
            decision_id: "decision-0000".into(),
            policy_id: "policy-a".into(),
            component: "scheduler".into(),
            event: "dispatch".into(),
            outcome: "ok".into(),
            error_code: None,
            sequence: 0,
            virtual_time_micros: 100,
        }];
        run.random_transcript.clear();
        run.output_digest = digest_run(
            &run.fixture_id,
            run.seed,
            &run.random_transcript,
            &run.events,
        );

        let err = validate_replay_input(&run, Some("model://snapshot/fix-1")).unwrap_err();
        assert_eq!(err.code, ReplayInputErrorCode::CorruptedTranscript);
        assert!(err.message.contains("length mismatch"));
    }

    #[test]
    fn replay_input_validation_rejects_corrupted_transcript_digest() {
        let mut run = make_run_result("abc", 1);
        run.events = vec![HarnessEvent {
            trace_id: "trace-a".into(),
            decision_id: "decision-0000".into(),
            policy_id: "policy-a".into(),
            component: "scheduler".into(),
            event: "dispatch".into(),
            outcome: "ok".into(),
            error_code: None,
            sequence: 0,
            virtual_time_micros: 100,
        }];
        run.random_transcript = vec![10];
        run.output_digest = "tampered".into();

        let err = validate_replay_input(&run, Some("model://snapshot/fix-1")).unwrap_err();
        assert_eq!(err.code, ReplayInputErrorCode::CorruptedTranscript);
        assert!(err.message.contains("run digest mismatch"));
    }

    // ── compare_counterfactual ────────────────────────────────────

    #[test]
    fn counterfactual_identical_runs() {
        let runner = DeterministicRunner::default();
        let fixture = valid_fixture();
        let a = runner.run_fixture(&fixture).unwrap();
        let b = runner.run_fixture(&fixture).unwrap();
        let delta = compare_counterfactual(&a, &b);
        assert!(!delta.digest_changed);
        assert_eq!(delta.changed_events, 0);
        assert_eq!(delta.changed_outcomes, 0);
        assert_eq!(delta.changed_error_codes, 0);
        assert!(delta.diverged_at_sequence.is_none());
        assert!(!delta.transcript_changed);
        assert!(delta.transcript_diverged_at_index.is_none());
        assert!(delta.divergence_samples.is_empty());
    }

    #[test]
    fn counterfactual_different_seeds() {
        let runner = DeterministicRunner::default();
        let f1 = valid_fixture();
        let mut f2 = valid_fixture();
        f2.seed = 999;
        f2.fixture_id = "fix-002".into();
        let a = runner.run_fixture(&f1).unwrap();
        let b = runner.run_fixture(&f2).unwrap();
        let delta = compare_counterfactual(&a, &b);
        assert!(delta.digest_changed);
    }

    #[test]
    fn counterfactual_different_event_lengths() {
        let mut a = make_run_result("a", 1);
        a.events.push(HarnessEvent {
            trace_id: "t".into(),
            decision_id: "d".into(),
            policy_id: "p".into(),
            component: "c".into(),
            event: "e".into(),
            outcome: "ok".into(),
            error_code: None,
            sequence: 0,
            virtual_time_micros: 0,
        });
        let b = make_run_result("b", 1);
        let delta = compare_counterfactual(&a, &b);
        assert_eq!(delta.changed_events, 1);
        assert_eq!(delta.diverged_at_sequence, Some(0));
        assert_eq!(delta.baseline_event_count, 1);
        assert_eq!(delta.counterfactual_event_count, 0);
        assert_eq!(delta.divergence_samples.len(), 1);
        assert_eq!(
            delta.divergence_samples[0].kind,
            CounterfactualDivergenceKind::MissingCounterfactualEvent
        );
    }

    #[test]
    fn counterfactual_outcome_diff() {
        let mut a = make_run_result("a", 1);
        let mut b = make_run_result("b", 1);
        let evt = HarnessEvent {
            trace_id: "t".into(),
            decision_id: "d".into(),
            policy_id: "p".into(),
            component: "c".into(),
            event: "e".into(),
            outcome: "ok".into(),
            error_code: None,
            sequence: 0,
            virtual_time_micros: 0,
        };
        a.events.push(evt.clone());
        let mut evt2 = evt;
        evt2.outcome = "fail".into();
        evt2.error_code = Some("FE-E2E-FAIL".into());
        b.events.push(evt2);
        let delta = compare_counterfactual(&a, &b);
        assert_eq!(delta.changed_outcomes, 1);
        assert_eq!(delta.changed_error_codes, 1);
        assert_eq!(delta.divergence_samples.len(), 1);
        assert_eq!(delta.divergence_samples[0].sequence, 0);
    }

    // ── RunReport ─────────────────────────────────────────────────

    #[test]
    fn run_report_from_result_pass() {
        let runner = DeterministicRunner::default();
        let result = runner.run_fixture(&valid_fixture()).unwrap();
        let report = RunReport::from_result(&result);
        assert!(report.pass);
        assert_eq!(report.event_count, 1);
        assert!(report.first_error_code.is_none());
    }

    #[test]
    fn run_report_from_result_with_error() {
        let mut f = valid_fixture();
        let mut meta = BTreeMap::new();
        meta.insert("error_code".into(), "E_BOOM".into());
        f.steps[0].metadata = meta;
        let runner = DeterministicRunner::default();
        let result = runner.run_fixture(&f).unwrap();
        let report = RunReport::from_result(&result);
        assert!(!report.pass);
        assert_eq!(report.first_error_code.as_deref(), Some("E_BOOM"));
    }

    #[test]
    fn run_report_to_markdown_contains_status() {
        let runner = DeterministicRunner::default();
        let result = runner.run_fixture(&valid_fixture()).unwrap();
        let report = RunReport::from_result(&result);
        let md = report.to_markdown();
        assert!(md.contains("status: `pass`"));
        assert!(md.contains("# E2E Run Report"));
    }

    #[test]
    fn run_report_serde_round_trip() {
        let runner = DeterministicRunner::default();
        let result = runner.run_fixture(&valid_fixture()).unwrap();
        let report = RunReport::from_result(&result);
        let json = serde_json::to_string(&report).unwrap();
        let back: RunReport = serde_json::from_str(&json).unwrap();
        assert_eq!(report, back);
    }

    // ── RunManifest / GoldenBaseline / SignedGoldenUpdate serde ───

    #[test]
    fn run_manifest_serde_round_trip() {
        let m = RunManifest {
            fixture_id: "f".into(),
            run_id: "r".into(),
            seed: 10,
            event_count: 5,
            output_digest: "abc".into(),
            replay_pointer: "replay://r".into(),
            model_snapshot_pointer: "model://snapshot/f/seed/10".into(),
            artifact_schema_version: 1,
            environment_fingerprint: ReplayEnvironmentFingerprint {
                os: "linux".into(),
                architecture: "x86_64".into(),
                family: "unix".into(),
                pointer_width_bits: 64,
                endian: "little".into(),
            },
        };
        let json = serde_json::to_string(&m).unwrap();
        let back: RunManifest = serde_json::from_str(&json).unwrap();
        assert_eq!(m, back);
    }

    #[test]
    fn golden_baseline_serde_round_trip() {
        let g = GoldenBaseline {
            fixture_id: "f".into(),
            output_digest: "d".into(),
            source_run_id: "r".into(),
        };
        let json = serde_json::to_string(&g).unwrap();
        let back: GoldenBaseline = serde_json::from_str(&json).unwrap();
        assert_eq!(g, back);
    }

    #[test]
    fn signed_golden_update_serde_round_trip() {
        let u = SignedGoldenUpdate {
            update_id: "u".into(),
            fixture_id: "f".into(),
            previous_digest: "p".into(),
            next_digest: "n".into(),
            source_run_id: "r".into(),
            signer: "bob".into(),
            signature: "sig".into(),
            rationale: "reason".into(),
        };
        let json = serde_json::to_string(&u).unwrap();
        let back: SignedGoldenUpdate = serde_json::from_str(&json).unwrap();
        assert_eq!(u, back);
    }

    // ── ReplayVerification serde ──────────────────────────────────

    #[test]
    fn replay_verification_serde_round_trip() {
        let v = ReplayVerification {
            matches: true,
            expected_digest: "e".into(),
            actual_digest: "a".into(),
            reason: None,
            mismatch_kind: None,
            diverged_event_sequence: None,
            transcript_mismatch_index: None,
            expected_event_count: 0,
            actual_event_count: 0,
            expected_transcript_len: 0,
            actual_transcript_len: 0,
        };
        let json = serde_json::to_string(&v).unwrap();
        let back: ReplayVerification = serde_json::from_str(&json).unwrap();
        assert_eq!(v, back);
    }

    #[test]
    fn cross_machine_replay_diagnosis_serde_round_trip() {
        let d = CrossMachineReplayDiagnosis {
            cross_machine_match: false,
            replay_verification: ReplayVerification {
                matches: false,
                expected_digest: "a".into(),
                actual_digest: "b".into(),
                reason: Some("digest mismatch".into()),
                mismatch_kind: Some(ReplayMismatchKind::Digest),
                diverged_event_sequence: None,
                transcript_mismatch_index: None,
                expected_event_count: 0,
                actual_event_count: 0,
                expected_transcript_len: 0,
                actual_transcript_len: 0,
            },
            expected_environment: ReplayEnvironmentFingerprint {
                os: "linux".into(),
                architecture: "x86_64".into(),
                family: "unix".into(),
                pointer_width_bits: 64,
                endian: "little".into(),
            },
            actual_environment: ReplayEnvironmentFingerprint {
                os: "windows".into(),
                architecture: "x86_64".into(),
                family: "windows".into(),
                pointer_width_bits: 64,
                endian: "little".into(),
            },
            environment_mismatches: vec!["os".into(), "family".into()],
            diagnosis: Some(
                "replay mismatch: digest mismatch; environment mismatch fields: os, family".into(),
            ),
        };
        let json = serde_json::to_string(&d).unwrap();
        let back: CrossMachineReplayDiagnosis = serde_json::from_str(&json).unwrap();
        assert_eq!(d, back);
    }

    // ── CounterfactualDelta serde ─────────────────────────────────

    #[test]
    fn counterfactual_delta_serde_round_trip() {
        let d = CounterfactualDelta {
            baseline_run_id: "b".into(),
            counterfactual_run_id: "c".into(),
            digest_changed: true,
            diverged_at_sequence: Some(3),
            changed_events: 5,
            changed_outcomes: 2,
            changed_error_codes: 1,
            baseline_event_count: 6,
            counterfactual_event_count: 5,
            transcript_changed: true,
            transcript_diverged_at_index: Some(2),
            divergence_samples: vec![CounterfactualDivergenceSample {
                sequence: 3,
                kind: CounterfactualDivergenceKind::EventMismatch,
                baseline_component: Some("baseline".into()),
                counterfactual_component: Some("counterfactual".into()),
                baseline_event: Some("evaluate".into()),
                counterfactual_event: Some("evaluate".into()),
                baseline_outcome: Some("ok".into()),
                counterfactual_outcome: Some("error".into()),
                baseline_error_code: None,
                counterfactual_error_code: Some("FE-ERR".into()),
            }],
        };
        let json = serde_json::to_string(&d).unwrap();
        let back: CounterfactualDelta = serde_json::from_str(&json).unwrap();
        assert_eq!(d, back);
    }

    // ── GoldenVerificationError Display ───────────────────────────

    #[test]
    fn golden_error_display_missing() {
        let e = GoldenVerificationError::MissingBaseline {
            fixture_id: "fix-1".into(),
        };
        assert!(e.to_string().contains("fix-1"));
    }

    #[test]
    fn golden_error_display_invalid() {
        let inner = io::Error::other("bad");
        let e = GoldenVerificationError::InvalidBaseline(inner);
        assert!(e.to_string().contains("invalid golden baseline"));
        assert!(e.source().is_some());
    }

    #[test]
    fn golden_error_display_mismatch() {
        let e = GoldenVerificationError::DigestMismatch {
            expected: "aaa".into(),
            actual: "bbb".into(),
        };
        assert!(e.to_string().contains("aaa"));
        assert!(e.to_string().contains("bbb"));
    }

    // ── fnv1a64 ───────────────────────────────────────────────────

    #[test]
    fn fnv1a64_deterministic() {
        let a = fnv1a64(b"hello");
        let b = fnv1a64(b"hello");
        assert_eq!(a, b);
    }

    #[test]
    fn fnv1a64_different_inputs() {
        assert_ne!(fnv1a64(b"hello"), fnv1a64(b"world"));
    }

    #[test]
    fn fnv1a64_empty() {
        let h = fnv1a64(b"");
        // FNV-1a offset basis
        assert_eq!(h, 0xcbf2_9ce4_8422_2325);
    }

    // ── digest_hex ────────────────────────────────────────────────

    #[test]
    fn digest_hex_deterministic() {
        let a = digest_hex(b"test");
        let b = digest_hex(b"test");
        assert_eq!(a, b);
    }

    #[test]
    fn digest_hex_length() {
        let h = digest_hex(b"test");
        assert_eq!(h.len(), 16); // 16 hex chars for u64
    }

    // ── sanitize_label ────────────────────────────────────────────

    #[test]
    fn sanitize_label_alphanumeric_passthrough() {
        assert_eq!(sanitize_label("hello-world_123"), "hello-world_123");
    }

    #[test]
    fn sanitize_label_replaces_special() {
        assert_eq!(sanitize_label("a/b:c d"), "a-b-c-d");
    }

    #[test]
    fn sanitize_label_empty() {
        assert_eq!(sanitize_label(""), "");
    }

    // ── HarnessEvent serde ────────────────────────────────────────

    #[test]
    fn harness_event_serde_round_trip() {
        let ev = HarnessEvent {
            trace_id: "t".into(),
            decision_id: "d".into(),
            policy_id: "p".into(),
            component: "c".into(),
            event: "e".into(),
            outcome: "ok".into(),
            error_code: Some("E001".into()),
            sequence: 7,
            virtual_time_micros: 42,
        };
        let json = serde_json::to_string(&ev).unwrap();
        let back: HarnessEvent = serde_json::from_str(&json).unwrap();
        assert_eq!(ev, back);
    }

    // ── RunResult serde ───────────────────────────────────────────

    #[test]
    fn run_result_serde_round_trip() {
        let runner = DeterministicRunner::default();
        let result = runner.run_fixture(&valid_fixture()).unwrap();
        let json = serde_json::to_string(&result).unwrap();
        let back: RunResult = serde_json::from_str(&json).unwrap();
        assert_eq!(result, back);
    }

    // ── digest_run ────────────────────────────────────────────────

    #[test]
    fn digest_run_deterministic() {
        let a = digest_run("fix", 1, &[10, 20], &[]);
        let b = digest_run("fix", 1, &[10, 20], &[]);
        assert_eq!(a, b);
    }

    #[test]
    fn digest_run_changes_with_seed() {
        let a = digest_run("fix", 1, &[10], &[]);
        let b = digest_run("fix", 2, &[10], &[]);
        assert_ne!(a, b);
    }

    // ── LogAssertionError Display ─────────────────────────────────

    #[test]
    fn log_assertion_error_display() {
        let e = LogAssertionError {
            missing: vec![
                LogExpectation {
                    component: "a".into(),
                    event: "b".into(),
                    outcome: "c".into(),
                    error_code: None,
                },
                LogExpectation {
                    component: "d".into(),
                    event: "e".into(),
                    outcome: "f".into(),
                    error_code: None,
                },
            ],
        };
        assert!(e.to_string().contains("2"));
    }

    // ── FixtureStore / GoldenStore / ArtifactCollector with tmpdir

    #[test]
    fn fixture_store_save_and_load() {
        let dir = std::env::temp_dir().join(format!("e2e_test_fixture_{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        let store = FixtureStore::new(&dir).unwrap();
        let fixture = valid_fixture();
        let path = store.save_fixture(&fixture).unwrap();
        assert!(path.exists());
        let loaded = store.load_fixture(&path).unwrap();
        assert_eq!(fixture, loaded);
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn fixture_store_rejects_invalid_fixture() {
        let dir = std::env::temp_dir().join(format!("e2e_test_invalid_{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        let store = FixtureStore::new(&dir).unwrap();
        let mut f = valid_fixture();
        f.steps.clear();
        assert!(store.save_fixture(&f).is_err());
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn golden_store_write_and_verify() {
        let dir = std::env::temp_dir().join(format!("e2e_test_golden_{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        let store = GoldenStore::new(&dir).unwrap();
        let runner = DeterministicRunner::default();
        let result = runner.run_fixture(&valid_fixture()).unwrap();
        store.write_baseline(&result).unwrap();
        assert!(store.verify_run(&result).is_ok());
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn golden_store_verify_missing_baseline() {
        let dir = std::env::temp_dir().join(format!("e2e_test_no_bl_{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        let store = GoldenStore::new(&dir).unwrap();
        let result = make_run_result("abc", 1);
        let err = store.verify_run(&result).unwrap_err();
        assert!(matches!(
            err,
            GoldenVerificationError::MissingBaseline { .. }
        ));
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn golden_store_verify_digest_mismatch() {
        let dir = std::env::temp_dir().join(format!("e2e_test_mismatch_{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        let store = GoldenStore::new(&dir).unwrap();
        let runner = DeterministicRunner::default();
        let result = runner.run_fixture(&valid_fixture()).unwrap();
        store.write_baseline(&result).unwrap();
        let mut altered = result.clone();
        altered.output_digest = "tampered".into();
        let err = store.verify_run(&altered).unwrap_err();
        assert!(matches!(
            err,
            GoldenVerificationError::DigestMismatch { .. }
        ));
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn golden_store_signed_update() {
        let dir = std::env::temp_dir().join(format!("e2e_test_signed_{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        let store = GoldenStore::new(&dir).unwrap();
        let runner = DeterministicRunner::default();
        let result = runner.run_fixture(&valid_fixture()).unwrap();
        store.write_baseline(&result).unwrap();
        let path = store
            .write_signed_update(&result, "alice", "sig123", "intentional update")
            .unwrap();
        assert!(path.exists());
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn golden_store_signed_update_empty_signer() {
        let dir = std::env::temp_dir().join(format!("e2e_test_nosig_{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        let store = GoldenStore::new(&dir).unwrap();
        let runner = DeterministicRunner::default();
        let result = runner.run_fixture(&valid_fixture()).unwrap();
        store.write_baseline(&result).unwrap();
        assert!(
            store
                .write_signed_update(&result, " ", "sig", "reason")
                .is_err()
        );
        assert!(
            store
                .write_signed_update(&result, "alice", "", "reason")
                .is_err()
        );
        assert!(
            store
                .write_signed_update(&result, "alice", "sig", "  ")
                .is_err()
        );
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn artifact_collector_collect() {
        let dir = std::env::temp_dir().join(format!("e2e_test_artifacts_{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        let collector = ArtifactCollector::new(&dir).unwrap();
        let runner = DeterministicRunner::default();
        let result = runner.run_fixture(&valid_fixture()).unwrap();
        let artifacts = collector.collect(&result).unwrap();
        assert!(artifacts.manifest_path.exists());
        assert!(artifacts.events_path.exists());
        assert!(artifacts.evidence_linkage_path.exists());
        assert!(artifacts.report_json_path.exists());
        assert!(artifacts.report_markdown_path.exists());
        let completeness = audit_collected_artifacts(&artifacts);
        assert!(completeness.complete);
        assert_eq!(completeness.event_count, result.events.len());
        assert_eq!(completeness.linkage_count, result.events.len());
        let _ = fs::remove_dir_all(&dir);
    }

    // -- Enrichment: PearlTower 2026-02-26 --

    #[test]
    fn replay_input_error_code_serde_roundtrip() {
        let variants = [
            ReplayInputErrorCode::MissingModelSnapshot,
            ReplayInputErrorCode::PartialTrace,
            ReplayInputErrorCode::CorruptedTranscript,
        ];
        for v in &variants {
            let json = serde_json::to_string(v).unwrap();
            let back: ReplayInputErrorCode = serde_json::from_str(&json).unwrap();
            assert_eq!(*v, back);
        }
    }

    #[test]
    fn replay_input_error_serde_roundtrip() {
        let err = ReplayInputError {
            code: ReplayInputErrorCode::PartialTrace,
            message: "trace incomplete".into(),
        };
        let json = serde_json::to_string(&err).unwrap();
        let back: ReplayInputError = serde_json::from_str(&json).unwrap();
        assert_eq!(err, back);
    }

    #[test]
    fn replay_mismatch_kind_serde_roundtrip() {
        let variants = [
            ReplayMismatchKind::Digest,
            ReplayMismatchKind::EventStream,
            ReplayMismatchKind::RandomTranscript,
        ];
        for v in &variants {
            let json = serde_json::to_string(v).unwrap();
            let back: ReplayMismatchKind = serde_json::from_str(&json).unwrap();
            assert_eq!(*v, back);
        }
    }

    #[test]
    fn counterfactual_divergence_kind_serde_roundtrip() {
        let variants = [
            CounterfactualDivergenceKind::EventMismatch,
            CounterfactualDivergenceKind::MissingBaselineEvent,
            CounterfactualDivergenceKind::MissingCounterfactualEvent,
        ];
        for v in &variants {
            let json = serde_json::to_string(v).unwrap();
            let back: CounterfactualDivergenceKind = serde_json::from_str(&json).unwrap();
            assert_eq!(*v, back);
        }
    }

    #[test]
    fn scenario_class_serde_roundtrip() {
        let variants = [
            ScenarioClass::Baseline,
            ScenarioClass::Differential,
            ScenarioClass::Chaos,
            ScenarioClass::Stress,
            ScenarioClass::FaultInjection,
            ScenarioClass::CrossArch,
        ];
        for v in &variants {
            let json = serde_json::to_string(v).unwrap();
            let back: ScenarioClass = serde_json::from_str(&json).unwrap();
            assert_eq!(*v, back);
        }
    }

    #[test]
    fn fixture_validation_error_display_all_distinct() {
        let variants = vec![
            FixtureValidationError::MissingFixtureId,
            FixtureValidationError::MissingPolicyId,
            FixtureValidationError::MissingSteps,
            FixtureValidationError::UnsupportedVersion {
                expected: 1,
                actual: 2,
            },
            FixtureValidationError::InvalidStep {
                index: 0,
                reason: "bad".into(),
            },
        ];
        let mut set = std::collections::BTreeSet::new();
        for v in &variants {
            set.insert(v.to_string());
        }
        assert_eq!(set.len(), variants.len());
    }

    #[test]
    fn fixture_migration_error_display_all_distinct() {
        let variants = vec![
            FixtureMigrationError::InvalidFixturePayload {
                message: "bad json".into(),
            },
            FixtureMigrationError::UnsupportedVersion {
                expected: 1,
                actual: 3,
            },
            FixtureMigrationError::InvalidMigratedFixture {
                message: "schema fail".into(),
            },
        ];
        let mut set = std::collections::BTreeSet::new();
        for v in &variants {
            set.insert(v.to_string());
        }
        assert_eq!(set.len(), variants.len());
    }

    #[test]
    fn replay_input_error_code_as_str_all_distinct() {
        let variants = [
            ReplayInputErrorCode::MissingModelSnapshot,
            ReplayInputErrorCode::PartialTrace,
            ReplayInputErrorCode::CorruptedTranscript,
        ];
        let mut set = std::collections::BTreeSet::new();
        for v in &variants {
            set.insert(v.as_str());
        }
        assert_eq!(set.len(), variants.len());
    }

    #[test]
    fn scenario_matrix_entry_serde_roundtrip() {
        let entry = ScenarioMatrixEntry {
            scenario_id: "stress-1".into(),
            scenario_class: ScenarioClass::Stress,
            fixture: valid_fixture(),
            baseline_scenario_id: None,
            chaos_profile: None,
            unit_anchor_ids: vec!["unit.e2e_harness.scenario_matrix_entry_serde_roundtrip".into()],
            target_arch: Some("x86_64".into()),
            worker_pool: None,
        };
        let json = serde_json::to_string(&entry).unwrap();
        let back: ScenarioMatrixEntry = serde_json::from_str(&json).unwrap();
        assert_eq!(entry, back);
    }

    // -- Enrichment: PearlTower 2026-03-02 --

    #[test]
    fn scenario_class_all_constant_and_as_str_distinct() {
        assert_eq!(ScenarioClass::ALL.len(), 6);
        let mut set = std::collections::BTreeSet::new();
        for class in &ScenarioClass::ALL {
            set.insert(class.as_str());
        }
        assert_eq!(set.len(), 6);
    }

    #[test]
    fn evaluate_replay_performance_zero_wall_time() {
        let run = make_run_result("abc", 1);
        let perf = evaluate_replay_performance(&run, 0);
        assert_eq!(perf.speedup_milli, u64::MAX);
        assert!(perf.faster_than_realtime);
    }

    #[test]
    fn validate_replay_input_success_path() {
        let runner = DeterministicRunner::default();
        let result = runner.run_fixture(&valid_fixture()).unwrap();
        assert!(validate_replay_input(&result, Some("model://snapshot/fix-001")).is_ok());
    }

    #[test]
    fn validate_replay_input_blank_model_pointer() {
        let run = make_run_result("abc", 1);
        let err = validate_replay_input(&run, Some("  ")).unwrap_err();
        assert_eq!(err.code, ReplayInputErrorCode::MissingModelSnapshot);
    }

    #[test]
    fn validate_replay_input_empty_trace_id() {
        let mut run = make_run_result("abc", 1);
        run.events = vec![HarnessEvent {
            trace_id: "".into(),
            decision_id: "d".into(),
            policy_id: "p".into(),
            component: "c".into(),
            event: "e".into(),
            outcome: "ok".into(),
            error_code: None,
            sequence: 0,
            virtual_time_micros: 0,
        }];
        run.random_transcript = vec![1];
        run.output_digest = digest_run(
            &run.fixture_id,
            run.seed,
            &run.random_transcript,
            &run.events,
        );
        let err = validate_replay_input(&run, Some("model://snap")).unwrap_err();
        assert_eq!(err.code, ReplayInputErrorCode::PartialTrace);
        assert!(err.message.contains("trace_id"));
    }

    #[test]
    fn validate_replay_input_empty_decision_id() {
        let mut run = make_run_result("abc", 1);
        run.events = vec![HarnessEvent {
            trace_id: "t".into(),
            decision_id: "  ".into(),
            policy_id: "p".into(),
            component: "c".into(),
            event: "e".into(),
            outcome: "ok".into(),
            error_code: None,
            sequence: 0,
            virtual_time_micros: 0,
        }];
        run.random_transcript = vec![1];
        run.output_digest = digest_run(
            &run.fixture_id,
            run.seed,
            &run.random_transcript,
            &run.events,
        );
        let err = validate_replay_input(&run, Some("model://snap")).unwrap_err();
        assert_eq!(err.code, ReplayInputErrorCode::PartialTrace);
        assert!(err.message.contains("decision_id"));
    }

    #[test]
    fn validate_replay_input_empty_policy_id() {
        let mut run = make_run_result("abc", 1);
        run.events = vec![HarnessEvent {
            trace_id: "t".into(),
            decision_id: "d".into(),
            policy_id: "".into(),
            component: "c".into(),
            event: "e".into(),
            outcome: "ok".into(),
            error_code: None,
            sequence: 0,
            virtual_time_micros: 0,
        }];
        run.random_transcript = vec![1];
        run.output_digest = digest_run(
            &run.fixture_id,
            run.seed,
            &run.random_transcript,
            &run.events,
        );
        let err = validate_replay_input(&run, Some("model://snap")).unwrap_err();
        assert_eq!(err.code, ReplayInputErrorCode::PartialTrace);
        assert!(err.message.contains("policy_id"));
    }

    #[test]
    fn build_evidence_linkage_direct() {
        let events = vec![
            HarnessEvent {
                trace_id: "t1".into(),
                decision_id: "d1".into(),
                policy_id: "p1".into(),
                component: "c".into(),
                event: "e".into(),
                outcome: "ok".into(),
                error_code: None,
                sequence: 0,
                virtual_time_micros: 10,
            },
            HarnessEvent {
                trace_id: "t1".into(),
                decision_id: "d2".into(),
                policy_id: "p1".into(),
                component: "c2".into(),
                event: "e2".into(),
                outcome: "ok".into(),
                error_code: None,
                sequence: 1,
                virtual_time_micros: 20,
            },
        ];
        let linkage = build_evidence_linkage(&events);
        assert_eq!(linkage.len(), 2);
        assert_eq!(linkage[0].trace_id, "t1");
        assert_eq!(linkage[0].decision_id, "d1");
        assert_eq!(linkage[0].event_sequence, 0);
        assert!(!linkage[0].evidence_hash.is_empty());
        assert_eq!(linkage[1].event_sequence, 1);
        // Deterministic: same input → same hash
        let linkage2 = build_evidence_linkage(&events);
        assert_eq!(linkage[0].evidence_hash, linkage2[0].evidence_hash);
    }

    #[test]
    fn replay_input_error_display_format() {
        let err = ReplayInputError {
            code: ReplayInputErrorCode::CorruptedTranscript,
            message: "bad data".into(),
        };
        let display = err.to_string();
        assert!(display.contains("corrupted_transcript"));
        assert!(display.contains("bad data"));
    }

    #[test]
    fn replay_environment_fingerprint_local_non_empty() {
        let fp = ReplayEnvironmentFingerprint::local();
        assert!(!fp.os.is_empty());
        assert!(!fp.architecture.is_empty());
        assert!(!fp.family.is_empty());
        assert!(fp.pointer_width_bits > 0);
        assert!(!fp.endian.is_empty());
    }

    #[test]
    fn replay_performance_serde_roundtrip() {
        let perf = ReplayPerformance {
            virtual_duration_micros: 500,
            wall_duration_micros: 250,
            faster_than_realtime: true,
            speedup_milli: 2000,
        };
        let json = serde_json::to_string(&perf).unwrap();
        let back: ReplayPerformance = serde_json::from_str(&json).unwrap();
        assert_eq!(perf, back);
    }

    #[test]
    fn evidence_linkage_record_serde_roundtrip() {
        let rec = EvidenceLinkageRecord {
            trace_id: "t".into(),
            decision_id: "d".into(),
            policy_id: "p".into(),
            event_sequence: 3,
            evidence_hash: "abc123".into(),
        };
        let json = serde_json::to_string(&rec).unwrap();
        let back: EvidenceLinkageRecord = serde_json::from_str(&json).unwrap();
        assert_eq!(rec, back);
    }

    #[test]
    fn parse_fixture_with_migration_invalid_json() {
        let err = parse_fixture_with_migration(b"not json at all").unwrap_err();
        assert!(matches!(
            err,
            FixtureMigrationError::InvalidFixturePayload { .. }
        ));
    }

    #[test]
    fn parse_fixture_with_migration_missing_fixture_version() {
        let payload = serde_json::json!({"fixture_id": "x"});
        let bytes = serde_json::to_vec(&payload).unwrap();
        let err = parse_fixture_with_migration(&bytes).unwrap_err();
        assert!(matches!(
            err,
            FixtureMigrationError::InvalidFixturePayload { .. }
        ));
        if let FixtureMigrationError::InvalidFixturePayload { message } = &err {
            assert!(message.contains("fixture_version"));
        }
    }

    #[test]
    fn parse_fixture_with_migration_v1_fails_validation() {
        let payload = serde_json::json!({
            "fixture_id": "",
            "fixture_version": 1,
            "seed": 1,
            "virtual_time_start_micros": 0,
            "policy_id": "pol",
            "steps": [{"component":"c","event":"e"}]
        });
        let bytes = serde_json::to_vec(&payload).unwrap();
        let err = parse_fixture_with_migration(&bytes).unwrap_err();
        assert!(matches!(
            err,
            FixtureMigrationError::InvalidMigratedFixture { .. }
        ));
    }

    #[test]
    fn cross_machine_replay_match_no_env_delta() {
        let a = make_run_result("abc", 1);
        let b = make_run_result("abc", 1);
        let env = ReplayEnvironmentFingerprint {
            os: "linux".into(),
            architecture: "x86_64".into(),
            family: "unix".into(),
            pointer_width_bits: 64,
            endian: "little".into(),
        };
        let diag = diagnose_cross_machine_replay(&a, &b, &env, &env);
        assert!(diag.cross_machine_match);
        assert!(diag.environment_mismatches.is_empty());
        assert!(diag.diagnosis.is_none());
    }

    #[test]
    fn cross_machine_replay_mismatch_no_env_delta() {
        let a = make_run_result("abc", 1);
        let b = make_run_result("xyz", 1);
        let env = ReplayEnvironmentFingerprint {
            os: "linux".into(),
            architecture: "x86_64".into(),
            family: "unix".into(),
            pointer_width_bits: 64,
            endian: "little".into(),
        };
        let diag = diagnose_cross_machine_replay(&a, &b, &env, &env);
        assert!(!diag.cross_machine_match);
        assert!(diag.environment_mismatches.is_empty());
        assert_eq!(
            diag.diagnosis.as_deref(),
            Some("replay mismatch: digest mismatch")
        );
    }

    #[test]
    fn select_rgc_advanced_scenario_matrix_filters_by_class() {
        let baseline_only = select_rgc_advanced_scenario_matrix(&[ScenarioClass::Baseline], true);
        assert!(!baseline_only.is_empty());
        for entry in &baseline_only {
            assert_eq!(entry.scenario_class, ScenarioClass::Baseline);
        }
    }

    #[test]
    fn select_rgc_advanced_scenario_matrix_excludes_fault_injection() {
        let no_fault = select_rgc_advanced_scenario_matrix(&[], false);
        for entry in &no_fault {
            assert_ne!(entry.scenario_class, ScenarioClass::FaultInjection);
        }
        let with_fault = select_rgc_advanced_scenario_matrix(&[], true);
        let has_fault = with_fault
            .iter()
            .any(|e| e.scenario_class == ScenarioClass::FaultInjection);
        assert!(has_fault);
    }

    #[test]
    fn counterfactual_missing_baseline_event() {
        let a = make_run_result("a", 1);
        let mut b = make_run_result("b", 1);
        b.events.push(HarnessEvent {
            trace_id: "t".into(),
            decision_id: "d".into(),
            policy_id: "p".into(),
            component: "c".into(),
            event: "e".into(),
            outcome: "ok".into(),
            error_code: None,
            sequence: 0,
            virtual_time_micros: 0,
        });
        let delta = compare_counterfactual(&a, &b);
        assert_eq!(delta.changed_events, 1);
        assert_eq!(delta.diverged_at_sequence, Some(0));
        assert_eq!(delta.divergence_samples.len(), 1);
        assert_eq!(
            delta.divergence_samples[0].kind,
            CounterfactualDivergenceKind::MissingBaselineEvent
        );
    }

    #[test]
    fn deterministic_runner_config_serde_roundtrip() {
        let cfg = DeterministicRunnerConfig {
            trace_prefix: "my-prefix".into(),
        };
        let json = serde_json::to_string(&cfg).unwrap();
        let back: DeterministicRunnerConfig = serde_json::from_str(&json).unwrap();
        assert_eq!(cfg, back);
    }

    #[test]
    fn artifact_completeness_report_serde_roundtrip() {
        let report = ArtifactCompletenessReport {
            complete: true,
            missing_files: vec![],
            diagnostics: vec!["note".into()],
            event_count: 5,
            linkage_count: 5,
        };
        let json = serde_json::to_string(&report).unwrap();
        let back: ArtifactCompletenessReport = serde_json::from_str(&json).unwrap();
        assert_eq!(report, back);
    }

    // -- Enrichment: PearlTower 2026-03-02 batch 2 --

    #[test]
    fn scenario_class_as_str_exact_values() {
        assert_eq!(ScenarioClass::Baseline.as_str(), "baseline");
        assert_eq!(ScenarioClass::Differential.as_str(), "differential");
        assert_eq!(ScenarioClass::Chaos.as_str(), "chaos");
        assert_eq!(ScenarioClass::Stress.as_str(), "stress");
        assert_eq!(ScenarioClass::FaultInjection.as_str(), "fault_injection");
        assert_eq!(ScenarioClass::CrossArch.as_str(), "cross_arch");
    }

    #[test]
    fn golden_verification_error_source_none_for_non_io() {
        let missing = GoldenVerificationError::MissingBaseline {
            fixture_id: "f".into(),
        };
        assert!(missing.source().is_none());

        let mismatch = GoldenVerificationError::DigestMismatch {
            expected: "a".into(),
            actual: "b".into(),
        };
        assert!(mismatch.source().is_none());
    }

    #[test]
    fn run_report_to_markdown_fail_status() {
        let mut f = valid_fixture();
        let mut meta = BTreeMap::new();
        meta.insert("error_code".into(), "FE-ERR-42".into());
        f.steps[0].metadata = meta;
        let runner = DeterministicRunner::default();
        let result = runner.run_fixture(&f).unwrap();
        let report = RunReport::from_result(&result);
        let md = report.to_markdown();
        assert!(md.contains("status: `fail`"));
        assert!(md.contains("first_error_code: `FE-ERR-42`"));
    }

    #[test]
    fn run_report_to_markdown_contains_all_fields() {
        let runner = DeterministicRunner::default();
        let result = runner.run_fixture(&valid_fixture()).unwrap();
        let report = RunReport::from_result(&result);
        let md = report.to_markdown();
        assert!(md.contains(&format!("fixture_id: `{}`", report.fixture_id)));
        assert!(md.contains(&format!("run_id: `{}`", report.run_id)));
        assert!(md.contains(&format!("event_count: `{}`", report.event_count)));
        assert!(md.contains(&format!("output_digest: `{}`", report.output_digest)));
        assert!(md.contains("first_error_code: `none`"));
    }

    #[test]
    fn build_evidence_linkage_empty_events() {
        let linkage = build_evidence_linkage(&[]);
        assert!(linkage.is_empty());
    }

    #[test]
    fn virtual_clock_advance_zero_is_noop() {
        let mut clock = VirtualClock::new(500);
        clock.advance(0);
        assert_eq!(clock.now_micros(), 500);
    }

    #[test]
    fn counterfactual_transcript_changed_flag() {
        let mut a = make_run_result("a", 1);
        let mut b = make_run_result("b", 2);
        a.random_transcript = vec![10, 20, 30];
        b.random_transcript = vec![10, 20, 99];
        let delta = compare_counterfactual(&a, &b);
        assert!(delta.transcript_changed);
        assert_eq!(delta.transcript_diverged_at_index, Some(2));
    }

    #[test]
    fn run_report_first_error_code_picks_first_among_multiple() {
        let mut f = valid_fixture();
        f.steps.push(ScenarioStep {
            component: "db".into(),
            event: "query".into(),
            advance_micros: 50,
            metadata: {
                let mut m = BTreeMap::new();
                m.insert("error_code".into(), "FE-SECOND".into());
                m
            },
        });
        let mut meta = BTreeMap::new();
        meta.insert("error_code".into(), "FE-FIRST".into());
        f.steps[0].metadata = meta;
        let runner = DeterministicRunner::default();
        let result = runner.run_fixture(&f).unwrap();
        let report = RunReport::from_result(&result);
        assert!(!report.pass);
        assert_eq!(report.first_error_code.as_deref(), Some("FE-FIRST"));
    }

    #[test]
    fn scenario_matrix_report_serde_roundtrip() {
        let report = ScenarioMatrixReport {
            schema_version: "v2".into(),
            summary_id: "sum-1".into(),
            total_scenarios: 2,
            pass_scenarios: 1,
            fail_scenarios: 1,
            scenario_packs: vec![],
        };
        let json = serde_json::to_string(&report).unwrap();
        let back: ScenarioMatrixReport = serde_json::from_str(&json).unwrap();
        assert_eq!(report, back);
    }

    #[test]
    fn scenario_artifact_paths_serde_roundtrip() {
        let paths = ScenarioArtifactPaths {
            manifest: "a/manifest.json".into(),
            events: "a/events.jsonl".into(),
            evidence_linkage: "a/evidence.json".into(),
            report_json: "a/report.json".into(),
            report_markdown: "a/report.md".into(),
        };
        let json = serde_json::to_string(&paths).unwrap();
        let back: ScenarioArtifactPaths = serde_json::from_str(&json).unwrap();
        assert_eq!(paths, back);
    }

    #[test]
    fn scenario_evidence_pack_serde_roundtrip() {
        let pack = ScenarioEvidencePack {
            scenario_id: "s1".into(),
            scenario_class: ScenarioClass::Baseline,
            baseline_scenario_id: None,
            chaos_profile: None,
            unit_anchor_ids: vec!["anchor1".into()],
            target_arch: None,
            worker_pool: Some("pool-1".into()),
            fixture_id: "fix".into(),
            run_id: "run".into(),
            output_digest: "digest".into(),
            event_count: 3,
            pass: true,
            first_error_code: None,
            replay_pointer: "replay://run".into(),
            artifact_paths: ScenarioArtifactPaths {
                manifest: "m.json".into(),
                events: "e.jsonl".into(),
                evidence_linkage: "l.json".into(),
                report_json: "r.json".into(),
                report_markdown: "r.md".into(),
            },
            completeness: ArtifactCompletenessReport {
                complete: true,
                missing_files: vec![],
                diagnostics: vec![],
                event_count: 3,
                linkage_count: 3,
            },
        };
        let json = serde_json::to_string(&pack).unwrap();
        let back: ScenarioEvidencePack = serde_json::from_str(&json).unwrap();
        assert_eq!(pack, back);
    }

    #[test]
    fn rgc_advanced_scenario_matrix_registry_all_6_classes() {
        let registry = rgc_advanced_scenario_matrix_registry();
        assert_eq!(registry.len(), 6);
        let classes: std::collections::BTreeSet<_> =
            registry.iter().map(|e| e.scenario_class.as_str()).collect();
        assert_eq!(classes.len(), 6);
    }

    #[test]
    fn select_rgc_advanced_empty_classes_returns_all_with_fault() {
        let all = select_rgc_advanced_scenario_matrix(&[], true);
        assert_eq!(all.len(), 6);
    }

    #[test]
    fn golden_verification_error_display_exact_format() {
        let e = GoldenVerificationError::MissingBaseline {
            fixture_id: "test-fixture".into(),
        };
        assert_eq!(
            e.to_string(),
            "missing golden baseline for fixture `test-fixture`"
        );
        let e2 = GoldenVerificationError::DigestMismatch {
            expected: "aaa".into(),
            actual: "bbb".into(),
        };
        assert_eq!(
            e2.to_string(),
            "golden digest mismatch: expected `aaa`, got `bbb`"
        );
    }

    #[test]
    fn replay_environment_fingerprint_serde_roundtrip_direct() {
        let fp = ReplayEnvironmentFingerprint {
            os: "macos".into(),
            architecture: "aarch64".into(),
            family: "unix".into(),
            pointer_width_bits: 64,
            endian: "little".into(),
        };
        let json = serde_json::to_string(&fp).unwrap();
        let back: ReplayEnvironmentFingerprint = serde_json::from_str(&json).unwrap();
        assert_eq!(fp, back);
    }

    #[test]
    fn replay_input_error_code_as_str_exact_values() {
        assert_eq!(
            ReplayInputErrorCode::MissingModelSnapshot.as_str(),
            "missing_model_snapshot"
        );
        assert_eq!(ReplayInputErrorCode::PartialTrace.as_str(), "partial_trace");
        assert_eq!(
            ReplayInputErrorCode::CorruptedTranscript.as_str(),
            "corrupted_transcript"
        );
    }

    #[test]
    fn fixture_migration_error_display_exact_content() {
        let e1 = FixtureMigrationError::InvalidFixturePayload {
            message: "bad json".into(),
        };
        assert_eq!(e1.to_string(), "invalid fixture payload: bad json");

        let e2 = FixtureMigrationError::UnsupportedVersion {
            expected: 1,
            actual: 5,
        };
        assert!(e2.to_string().contains("expected 1"));
        assert!(e2.to_string().contains("got 5"));

        let e3 = FixtureMigrationError::InvalidMigratedFixture {
            message: "missing field".into(),
        };
        assert_eq!(e3.to_string(), "invalid migrated fixture: missing field");
    }

    #[test]
    fn assert_structured_logs_with_matching_error_code() {
        let events = vec![HarnessEvent {
            trace_id: "t".into(),
            decision_id: "d".into(),
            policy_id: "p".into(),
            component: "db".into(),
            event: "query".into(),
            outcome: "error".into(),
            error_code: Some("E_TIMEOUT".into()),
            sequence: 0,
            virtual_time_micros: 0,
        }];
        let expectations = vec![LogExpectation {
            component: "db".into(),
            event: "query".into(),
            outcome: "error".into(),
            error_code: Some("E_TIMEOUT".into()),
        }];
        assert!(assert_structured_logs(&events, &expectations).is_ok());
    }

    #[test]
    fn runner_random_transcript_values_non_zero() {
        let runner = DeterministicRunner::default();
        let result = runner.run_fixture(&valid_fixture()).unwrap();
        for val in &result.random_transcript {
            assert_ne!(*val, 0, "transcript values should be non-zero");
        }
    }

    #[test]
    fn counterfactual_missing_counterfactual_event_sample_fields() {
        let mut a = make_run_result("a", 1);
        a.events.push(HarnessEvent {
            trace_id: "t".into(),
            decision_id: "d".into(),
            policy_id: "p".into(),
            component: "scheduler".into(),
            event: "dispatch".into(),
            outcome: "ok".into(),
            error_code: None,
            sequence: 0,
            virtual_time_micros: 0,
        });
        let b = make_run_result("b", 1);
        let delta = compare_counterfactual(&a, &b);
        let sample = &delta.divergence_samples[0];
        assert_eq!(
            sample.kind,
            CounterfactualDivergenceKind::MissingCounterfactualEvent
        );
        assert_eq!(sample.baseline_component.as_deref(), Some("scheduler"));
        assert!(sample.counterfactual_component.is_none());
        assert_eq!(sample.baseline_event.as_deref(), Some("dispatch"));
        assert!(sample.counterfactual_event.is_none());
    }

    #[test]
    fn counterfactual_missing_baseline_event_sample_fields() {
        let a = make_run_result("a", 1);
        let mut b = make_run_result("b", 1);
        b.events.push(HarnessEvent {
            trace_id: "t".into(),
            decision_id: "d".into(),
            policy_id: "p".into(),
            component: "runtime".into(),
            event: "execute".into(),
            outcome: "ok".into(),
            error_code: None,
            sequence: 0,
            virtual_time_micros: 0,
        });
        let delta = compare_counterfactual(&a, &b);
        let sample = &delta.divergence_samples[0];
        assert_eq!(
            sample.kind,
            CounterfactualDivergenceKind::MissingBaselineEvent
        );
        assert!(sample.baseline_component.is_none());
        assert_eq!(sample.counterfactual_component.as_deref(), Some("runtime"));
        assert!(sample.baseline_event.is_none());
        assert_eq!(sample.counterfactual_event.as_deref(), Some("execute"));
    }

    #[test]
    fn counterfactual_divergence_sample_serde_roundtrip() {
        let sample = CounterfactualDivergenceSample {
            sequence: 5,
            kind: CounterfactualDivergenceKind::MissingBaselineEvent,
            baseline_component: None,
            counterfactual_component: Some("c".into()),
            baseline_event: None,
            counterfactual_event: Some("e".into()),
            baseline_outcome: None,
            counterfactual_outcome: Some("ok".into()),
            baseline_error_code: None,
            counterfactual_error_code: None,
        };
        let json = serde_json::to_string(&sample).unwrap();
        let back: CounterfactualDivergenceSample = serde_json::from_str(&json).unwrap();
        assert_eq!(sample, back);
    }

    #[test]
    fn cross_machine_replay_pointer_width_mismatch() {
        let a = make_run_result("abc", 1);
        let b = make_run_result("abc", 1);
        let env_a = ReplayEnvironmentFingerprint {
            os: "linux".into(),
            architecture: "x86_64".into(),
            family: "unix".into(),
            pointer_width_bits: 64,
            endian: "little".into(),
        };
        let env_b = ReplayEnvironmentFingerprint {
            os: "linux".into(),
            architecture: "x86_64".into(),
            family: "unix".into(),
            pointer_width_bits: 32,
            endian: "little".into(),
        };
        let diag = diagnose_cross_machine_replay(&a, &b, &env_a, &env_b);
        assert!(diag.cross_machine_match);
        assert_eq!(
            diag.environment_mismatches,
            vec!["pointer_width_bits".to_string()]
        );
    }

    #[test]
    fn cross_machine_replay_endian_mismatch() {
        let a = make_run_result("abc", 1);
        let b = make_run_result("abc", 1);
        let env_a = ReplayEnvironmentFingerprint {
            os: "linux".into(),
            architecture: "mips".into(),
            family: "unix".into(),
            pointer_width_bits: 32,
            endian: "big".into(),
        };
        let env_b = ReplayEnvironmentFingerprint {
            os: "linux".into(),
            architecture: "mips".into(),
            family: "unix".into(),
            pointer_width_bits: 32,
            endian: "little".into(),
        };
        let diag = diagnose_cross_machine_replay(&a, &b, &env_a, &env_b);
        assert!(diag.cross_machine_match);
        assert_eq!(diag.environment_mismatches, vec!["endian".to_string()]);
    }

    #[test]
    fn artifact_completeness_report_with_missing_files() {
        let report = ArtifactCompletenessReport {
            complete: false,
            missing_files: vec!["manifest".into(), "events".into()],
            diagnostics: vec![],
            event_count: 0,
            linkage_count: 0,
        };
        assert!(!report.complete);
        assert_eq!(report.missing_files.len(), 2);
        let json = serde_json::to_string(&report).unwrap();
        let back: ArtifactCompletenessReport = serde_json::from_str(&json).unwrap();
        assert_eq!(report, back);
    }

    #[test]
    fn rgc_advanced_scenario_matrix_registry_sorted() {
        let registry = rgc_advanced_scenario_matrix_registry();
        for window in registry.windows(2) {
            assert!(window[0].scenario_id <= window[1].scenario_id);
        }
    }

    #[test]
    fn fixture_validate_whitespace_only_fixture_id() {
        let mut f = valid_fixture();
        f.fixture_id = "   \t  ".into();
        assert!(matches!(
            f.validate(),
            Err(FixtureValidationError::MissingFixtureId)
        ));
    }

    #[test]
    fn fixture_validate_whitespace_only_policy_id() {
        let mut f = valid_fixture();
        f.policy_id = " \n ".into();
        assert!(matches!(
            f.validate(),
            Err(FixtureValidationError::MissingPolicyId)
        ));
    }

    #[test]
    fn runner_run_id_format_contains_fixture_and_digest() {
        let runner = DeterministicRunner::default();
        let result = runner.run_fixture(&valid_fixture()).unwrap();
        assert!(result.run_id.starts_with("run-"));
        assert!(result.run_id.contains("fix-001"));
    }
}
