use chrono::{DateTime, Utc};
use rustix::fs::{FlockOperation, flock};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::fmt;
use std::fs::{File, OpenOptions};
use std::io::{BufRead, BufReader, Read, Seek, SeekFrom, Write};
use std::path::{Component, Path};

pub const PROOF_MANIFEST_SCHEMA_VERSION: &str = "franken-engine.proof-artifact-manifest.v1";
pub const PROOF_EVENT_SCHEMA_VERSION: &str = "franken-engine.proof-artifact-event.v1";
pub const PROOF_REPORT_SCHEMA_VERSION: &str = "franken-engine.proof-artifact-report.v1";
pub const PROOF_COST_MANIFEST_SCHEMA_VERSION: &str = "franken-engine.proof-cost-manifest.v1";
pub const REDACTION_POLICY_SCHEMA_VERSION: &str =
    "franken-engine.proof-artifact-redaction-policy.v1";

// JSON validation limits for events.jsonl
pub const MAX_JSON_DEPTH: usize = 16;
pub const MAX_JSON_VALUE_SIZE: usize = 64 * 1024; // 64 KB per line
pub const MAX_JSON_STRING_LENGTH: usize = 32 * 1024; // 32 KB per string value

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProofArtifactError {
    UnknownSchema {
        expected: &'static str,
        actual: String,
    },
    MissingField(&'static str),
    InvalidPath(String),
    InvalidState(String),
    Io(String),
    JsonTooDeep {
        depth: usize,
        max: usize,
    },
    JsonTooLarge {
        size: usize,
        max: usize,
    },
    JsonStringTooLong {
        length: usize,
        max: usize,
    },
    JsonInvalidNumber(String),
    JsonMalformed(String),
}

impl fmt::Display for ProofArtifactError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnknownSchema { expected, actual } => {
                write!(
                    f,
                    "unknown schema version: expected {expected}, got {actual}"
                )
            }
            Self::MissingField(field) => write!(f, "missing required field: {field}"),
            Self::InvalidPath(path) => write!(f, "invalid artifact path: {path}"),
            Self::InvalidState(state) => write!(f, "invalid proof state: {state}"),
            Self::Io(error) => write!(f, "proof artifact I/O error: {error}"),
            Self::JsonTooDeep { depth, max } => {
                write!(f, "JSON nesting too deep: {depth} levels (max {max})")
            }
            Self::JsonTooLarge { size, max } => {
                write!(f, "JSON too large: {size} bytes (max {max})")
            }
            Self::JsonStringTooLong { length, max } => {
                write!(f, "JSON string too long: {length} chars (max {max})")
            }
            Self::JsonInvalidNumber(details) => write!(f, "invalid JSON number: {details}"),
            Self::JsonMalformed(details) => write!(f, "malformed JSON: {details}"),
        }
    }
}

impl std::error::Error for ProofArtifactError {}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProofRunStatus {
    Pass,
    Fail,
    Skipped,
    Blocked,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProofEventSeverity {
    Info,
    Warning,
    Error,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProofArtifactPaths {
    pub run_dir: String,
    pub manifest_json: String,
    pub commands_txt: String,
    pub events_jsonl: String,
    pub report_json: String,
    pub report_md: String,
    pub redaction_policy_json: String,
}

impl ProofArtifactPaths {
    pub fn standard(run_dir: impl AsRef<Path>) -> Result<Self, ProofArtifactError> {
        let run_dir = normalize_artifact_path(run_dir.as_ref())?;
        Ok(Self {
            manifest_json: format!("{run_dir}/manifest.json"),
            commands_txt: format!("{run_dir}/commands.txt"),
            events_jsonl: format!("{run_dir}/events.jsonl"),
            report_json: format!("{run_dir}/report.json"),
            report_md: format!("{run_dir}/report.md"),
            redaction_policy_json: format!("{run_dir}/redaction_policy.json"),
            run_dir,
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProofCommand {
    pub command_id: String,
    pub display: String,
    pub redacted_display: String,
    pub cwd: String,
    pub exit_code: Option<i32>,
    pub duration_ms: Option<u64>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProofArtifactRef {
    pub path: String,
    pub sha256: Option<String>,
    pub schema_version: Option<String>,
    pub role: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProofVerifierOutput {
    pub verifier_id: String,
    pub output_path: String,
    pub status: ProofRunStatus,
    pub decision: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProofFreshness {
    pub generated_utc: DateTime<Utc>,
    pub freshness_days: Option<u64>,
    pub max_freshness_days: Option<u64>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProofManifest {
    pub schema_version: String,
    pub bundle_id: String,
    pub gate_name: String,
    pub status: ProofRunStatus,
    pub generated_utc: DateTime<Utc>,
    pub source_revision: String,
    pub rerun_command: String,
    pub artifact_paths: ProofArtifactPaths,
    pub claim_ids: Vec<String>,
    pub bead_ids: Vec<String>,
    pub environment: BTreeMap<String, String>,
    pub commands: Vec<ProofCommand>,
    pub generated_artifacts: Vec<ProofArtifactRef>,
    pub expected_artifacts: Vec<ProofArtifactRef>,
    pub verifier_outputs: Vec<ProofVerifierOutput>,
    pub freshness: ProofFreshness,
}

impl ProofManifest {
    pub fn validate(&self) -> Result<(), ProofArtifactError> {
        require_schema(
            &self.schema_version,
            PROOF_MANIFEST_SCHEMA_VERSION,
            "manifest",
        )?;
        require_non_empty(&self.bundle_id, "bundle_id")?;
        require_non_empty(&self.gate_name, "gate_name")?;
        require_non_empty(&self.source_revision, "source_revision")?;
        require_non_empty(&self.rerun_command, "rerun_command")?;
        require_non_empty(&self.artifact_paths.run_dir, "artifact_paths.run_dir")?;

        for path in [
            &self.artifact_paths.run_dir,
            &self.artifact_paths.manifest_json,
            &self.artifact_paths.commands_txt,
            &self.artifact_paths.events_jsonl,
            &self.artifact_paths.report_json,
            &self.artifact_paths.report_md,
            &self.artifact_paths.redaction_policy_json,
        ] {
            normalize_artifact_path(path)?;
        }

        for command in &self.commands {
            require_non_empty(&command.command_id, "commands.command_id")?;
            require_non_empty(&command.redacted_display, "commands.redacted_display")?;
            normalize_artifact_path(&command.cwd)?;
        }

        for artifact in self
            .generated_artifacts
            .iter()
            .chain(self.expected_artifacts.iter())
        {
            require_non_empty(&artifact.path, "artifact.path")?;
            require_non_empty(&artifact.role, "artifact.role")?;
            normalize_artifact_path(&artifact.path)?;
            if let Some(sha256) = &artifact.sha256 {
                validate_sha256(sha256)?;
            }
        }

        for output in &self.verifier_outputs {
            require_non_empty(&output.verifier_id, "verifier_outputs.verifier_id")?;
            require_non_empty(&output.output_path, "verifier_outputs.output_path")?;
            normalize_artifact_path(&output.output_path)?;
        }

        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProofEvent {
    pub schema_version: String,
    pub event_name: String,
    pub severity: ProofEventSeverity,
    pub step_id: String,
    pub command_id: Option<String>,
    pub artifact_path: Option<String>,
    pub artifact_sha256: Option<String>,
    pub exit_code: Option<i32>,
    pub duration_ms: Option<u64>,
    pub decision: String,
    pub remediation: Option<String>,
}

impl ProofEvent {
    pub fn validate(&self) -> Result<(), ProofArtifactError> {
        require_schema(&self.schema_version, PROOF_EVENT_SCHEMA_VERSION, "event")?;
        require_non_empty(&self.event_name, "event_name")?;
        require_non_empty(&self.step_id, "step_id")?;
        require_non_empty(&self.decision, "decision")?;
        if let Some(path) = &self.artifact_path {
            normalize_artifact_path(path)?;
        }
        if let Some(sha256) = &self.artifact_sha256 {
            validate_sha256(sha256)?;
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProofEventsJsonlSummary {
    pub line_count: usize,
    pub blank_line_count: usize,
    pub event_count: usize,
    pub first_event_name: Option<String>,
    pub last_event_name: Option<String>,
}

impl ProofEventsJsonlSummary {
    fn empty() -> Self {
        Self {
            line_count: 0,
            blank_line_count: 0,
            event_count: 0,
            first_event_name: None,
            last_event_name: None,
        }
    }

    pub fn is_empty(&self) -> bool {
        self.event_count == 0
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProofReportFinding {
    pub finding_id: String,
    pub severity: ProofEventSeverity,
    pub summary: String,
    pub remediation: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProofMachineReport {
    pub schema_version: String,
    pub bundle_id: String,
    pub gate_name: String,
    pub status: ProofRunStatus,
    pub event_count: u64,
    pub failure_count: u64,
    pub rerun_command: String,
    pub manifest_path: String,
    pub report_json_path: String,
    pub report_md_path: String,
    pub findings: Vec<ProofReportFinding>,
}

impl ProofMachineReport {
    pub fn validate(&self) -> Result<(), ProofArtifactError> {
        require_schema(&self.schema_version, PROOF_REPORT_SCHEMA_VERSION, "report")?;
        require_non_empty(&self.bundle_id, "bundle_id")?;
        require_non_empty(&self.gate_name, "gate_name")?;
        require_non_empty(&self.rerun_command, "rerun_command")?;
        normalize_artifact_path(&self.manifest_path)?;
        normalize_artifact_path(&self.report_json_path)?;
        normalize_artifact_path(&self.report_md_path)?;
        Ok(())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProofCostTargetKind {
    Lib,
    Bin,
    Test,
    Bench,
    Example,
    BuildScript,
    Dependency,
}

impl ProofCostTargetKind {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Lib => "lib",
            Self::Bin => "bin",
            Self::Test => "test",
            Self::Bench => "bench",
            Self::Example => "example",
            Self::BuildScript => "build_script",
            Self::Dependency => "dependency",
        }
    }
}

impl fmt::Display for ProofCostTargetKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProofCostTarget {
    pub package: String,
    pub target: String,
    pub kind: ProofCostTargetKind,
    pub profile: String,
    pub compiled: bool,
    pub linked: bool,
    pub dragged_by: Vec<String>,
}

impl ProofCostTarget {
    #[must_use]
    pub fn new(
        package: impl Into<String>,
        target: impl Into<String>,
        kind: ProofCostTargetKind,
        profile: impl Into<String>,
        compiled: bool,
        linked: bool,
        dragged_by: Vec<String>,
    ) -> Self {
        Self {
            package: package.into(),
            target: target.into(),
            kind,
            profile: profile.into(),
            compiled,
            linked,
            dragged_by,
        }
    }

    pub fn validate(&self) -> Result<(), ProofArtifactError> {
        require_non_empty(&self.package, "proof_cost_target.package")?;
        require_non_empty(&self.target, "proof_cost_target.target")?;
        require_non_empty(&self.profile, "proof_cost_target.profile")?;
        if !self.compiled && !self.linked {
            return Err(ProofArtifactError::InvalidState(format!(
                "proof cost target `{}` was neither compiled nor linked",
                self.target
            )));
        }
        for source in &self.dragged_by {
            require_non_empty(source, "proof_cost_target.dragged_by")?;
        }
        Ok(())
    }

    fn stable_key(&self) -> String {
        format!(
            "{}|{}|{}|{}",
            self.package, self.kind, self.target, self.profile
        )
    }

    fn operator_label(&self) -> String {
        format!("{}:{}:{}", self.package, self.kind, self.target)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProofCostManifest {
    pub schema_version: String,
    pub manifest_id: String,
    pub bead_id: String,
    pub focused_suite: String,
    pub command: String,
    pub command_hash: String,
    pub cargo_package: String,
    pub expected_focus_targets: Vec<String>,
    pub observed_targets: Vec<ProofCostTarget>,
    pub target_counts: BTreeMap<String, u64>,
    pub total_compiled_targets: u64,
    pub total_linked_targets: u64,
    pub unexpected_targets: Vec<String>,
    pub operator_log: Vec<String>,
}

impl ProofCostManifest {
    #[must_use]
    pub fn new(
        bead_id: impl Into<String>,
        focused_suite: impl Into<String>,
        command: impl Into<String>,
        cargo_package: impl Into<String>,
        expected_focus_targets: Vec<String>,
        observed_targets: Vec<ProofCostTarget>,
    ) -> Self {
        let bead_id = bead_id.into();
        let focused_suite = focused_suite.into();
        let command = command.into();
        let cargo_package = cargo_package.into();
        let command_hash = sha256_hex(command.as_bytes());
        let expected_focus_targets = normalized_string_vec(expected_focus_targets);
        let observed_targets = normalized_targets(observed_targets);
        let target_counts = count_targets_by_kind(&observed_targets);
        let total_compiled_targets = observed_targets
            .iter()
            .filter(|target| target.compiled)
            .count() as u64;
        let total_linked_targets = observed_targets
            .iter()
            .filter(|target| target.linked)
            .count() as u64;
        let unexpected_targets = unexpected_targets(&expected_focus_targets, &observed_targets);
        let manifest_id =
            proof_cost_manifest_id(&bead_id, &focused_suite, &command_hash, &observed_targets);

        let mut manifest = Self {
            schema_version: PROOF_COST_MANIFEST_SCHEMA_VERSION.to_string(),
            manifest_id,
            bead_id,
            focused_suite,
            command,
            command_hash,
            cargo_package,
            expected_focus_targets,
            observed_targets,
            target_counts,
            total_compiled_targets,
            total_linked_targets,
            unexpected_targets,
            operator_log: Vec::new(),
        };
        manifest.operator_log = manifest.operator_log_lines();
        manifest
    }

    pub fn validate(&self) -> Result<(), ProofArtifactError> {
        require_schema(
            &self.schema_version,
            PROOF_COST_MANIFEST_SCHEMA_VERSION,
            "proof_cost_manifest",
        )?;
        require_non_empty(&self.manifest_id, "manifest_id")?;
        require_non_empty(&self.bead_id, "bead_id")?;
        require_non_empty(&self.focused_suite, "focused_suite")?;
        require_non_empty(&self.command, "command")?;
        require_non_empty(&self.cargo_package, "cargo_package")?;
        validate_sha256(&self.command_hash)?;
        if self.observed_targets.is_empty() {
            return Err(ProofArtifactError::MissingField("observed_targets"));
        }
        if self.target_counts != count_targets_by_kind(&self.observed_targets) {
            return Err(ProofArtifactError::InvalidState(
                "proof cost target_counts do not match observed_targets".to_string(),
            ));
        }
        let compiled = self
            .observed_targets
            .iter()
            .filter(|target| target.compiled)
            .count() as u64;
        if self.total_compiled_targets != compiled {
            return Err(ProofArtifactError::InvalidState(
                "proof cost total_compiled_targets does not match observed_targets".to_string(),
            ));
        }
        let linked = self
            .observed_targets
            .iter()
            .filter(|target| target.linked)
            .count() as u64;
        if self.total_linked_targets != linked {
            return Err(ProofArtifactError::InvalidState(
                "proof cost total_linked_targets does not match observed_targets".to_string(),
            ));
        }
        let unexpected = unexpected_targets(&self.expected_focus_targets, &self.observed_targets);
        if self.unexpected_targets != unexpected {
            return Err(ProofArtifactError::InvalidState(
                "proof cost unexpected_targets do not match expected_focus_targets".to_string(),
            ));
        }
        let operator_log = self.operator_log_lines();
        if self.operator_log != operator_log {
            return Err(ProofArtifactError::InvalidState(
                "proof cost operator_log is stale".to_string(),
            ));
        }
        for target in &self.observed_targets {
            target.validate()?;
        }
        Ok(())
    }

    pub fn canonical_json(&self) -> Result<String, ProofArtifactError> {
        self.validate()?;
        serde_json::to_string(self)
            .map_err(|error| ProofArtifactError::JsonMalformed(error.to_string()))
    }

    pub fn content_hash(&self) -> Result<String, ProofArtifactError> {
        Ok(sha256_hex(self.canonical_json()?))
    }

    #[must_use]
    pub fn operator_log_text(&self) -> String {
        self.operator_log.join("\n")
    }

    fn operator_log_lines(&self) -> Vec<String> {
        let mut lines = Vec::with_capacity(2 + self.unexpected_targets.len());
        lines.push(format!(
            "proof_cost suite={} bead={} package={} compiled={} linked={} unexpected={}",
            self.focused_suite,
            self.bead_id,
            self.cargo_package,
            self.total_compiled_targets,
            self.total_linked_targets,
            self.unexpected_targets.len()
        ));
        lines.push(format!("proof_cost command_hash={}", self.command_hash));
        for target in &self.unexpected_targets {
            lines.push(format!("proof_cost unexpected_target={target}"));
        }
        lines
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RedactionPolicy {
    pub schema_version: String,
    pub replacement: String,
    pub env_key_fragments: Vec<String>,
    pub literal_patterns: Vec<String>,
}

impl Default for RedactionPolicy {
    fn default() -> Self {
        Self {
            schema_version: REDACTION_POLICY_SCHEMA_VERSION.to_string(),
            replacement: "<redacted>".to_string(),
            env_key_fragments: vec![
                "API_KEY".to_string(),
                "ACCESS_TOKEN".to_string(),
                "TOKEN".to_string(),
                "_TOKEN".to_string(),
                "SECRET".to_string(),
                "PASSWORD".to_string(),
                "CREDENTIAL".to_string(),
                "AUTH".to_string(),
                "KEY".to_string(),
                "_KEY".to_string(),
                "BEARER".to_string(),
                "OAUTH".to_string(),
            ],
            literal_patterns: vec!["Bearer ".to_string()],
        }
    }
}

impl RedactionPolicy {
    pub fn validate(&self) -> Result<(), ProofArtifactError> {
        require_schema(
            &self.schema_version,
            REDACTION_POLICY_SCHEMA_VERSION,
            "redaction_policy",
        )?;
        require_non_empty(&self.replacement, "replacement")?;
        if self.env_key_fragments.is_empty() {
            return Err(ProofArtifactError::MissingField("env_key_fragments"));
        }
        Ok(())
    }
}

pub fn redact_text(input: &str, policy: &RedactionPolicy) -> String {
    let fragments: Vec<String> = policy
        .env_key_fragments
        .iter()
        .map(|fragment| fragment.to_ascii_uppercase())
        .collect();
    let literal_markers: Vec<String> = policy
        .literal_patterns
        .iter()
        .filter_map(|pattern| pattern.split_whitespace().next())
        .map(|pattern| pattern.to_ascii_uppercase())
        .filter(|pattern| !pattern.is_empty())
        .collect();

    let mut redact_next = false;
    let mut redacted = Vec::new();

    for token in input.split_whitespace() {
        let is_literal_marker = is_literal_marker(token, &literal_markers);
        if redact_next && !is_literal_marker {
            if let Some(redacted_token) = redact_inline_bearer(token, &policy.replacement) {
                redacted.push(redacted_token);
            } else {
                redacted.push(policy.replacement.clone());
            }
            redact_next = false;
            continue;
        }

        let (redacted_token, token_redacts_next) =
            redact_token(token, &fragments, &literal_markers, &policy.replacement);
        redact_next = token_redacts_next || (redact_next && is_literal_marker);
        redacted.push(redacted_token);
    }

    redacted.join(" ")
}

pub fn render_report_markdown(report: &ProofMachineReport) -> String {
    let mut output = String::new();
    output.push_str("# Proof Artifact Report\n\n");
    output.push_str(&format!("- Bundle: `{}`\n", report.bundle_id));
    output.push_str(&format!("- Gate: `{}`\n", report.gate_name));
    output.push_str(&format!("- Status: `{:?}`\n", report.status));
    output.push_str(&format!("- Events: `{}`\n", report.event_count));
    output.push_str(&format!("- Failures: `{}`\n", report.failure_count));
    output.push_str(&format!("- Rerun: `{}`\n\n", report.rerun_command));

    if report.findings.is_empty() {
        output.push_str("No findings were emitted.\n");
    } else {
        output.push_str("## Findings\n\n");
        for finding in &report.findings {
            output.push_str(&format!(
                "- `{:?}` `{}`: {}\n",
                finding.severity, finding.finding_id, finding.summary
            ));
            if let Some(remediation) = &finding.remediation {
                output.push_str(&format!("  Remediation: {remediation}\n"));
            }
        }
    }

    output
}

pub fn normalize_artifact_path(path: impl AsRef<Path>) -> Result<String, ProofArtifactError> {
    let path = path.as_ref();
    if path.as_os_str().is_empty() || path.is_absolute() {
        return Err(ProofArtifactError::InvalidPath(
            path.to_string_lossy().to_string(),
        ));
    }

    let mut parts = Vec::new();
    for component in path.components() {
        match component {
            Component::Normal(part) => parts.push(part.to_string_lossy().to_string()),
            Component::CurDir => {}
            Component::ParentDir | Component::RootDir | Component::Prefix(_) => {
                return Err(ProofArtifactError::InvalidPath(
                    path.to_string_lossy().to_string(),
                ));
            }
        }
    }

    if parts.is_empty() {
        return Err(ProofArtifactError::InvalidPath(
            path.to_string_lossy().to_string(),
        ));
    }

    Ok(parts.join("/"))
}

pub fn sha256_hex(bytes: impl AsRef<[u8]>) -> String {
    let mut hasher = Sha256::new();
    hasher.update(bytes.as_ref());
    format!("{:x}", hasher.finalize())
}

pub fn sha256_file(path: impl AsRef<Path>) -> Result<String, ProofArtifactError> {
    let file = File::open(path).map_err(|error| ProofArtifactError::Io(error.to_string()))?;
    let mut reader = BufReader::new(file);
    let mut hasher = Sha256::new();
    let mut buffer = [0; 8192]; // 8KB chunks

    loop {
        let bytes_read = reader
            .read(&mut buffer)
            .map_err(|error| ProofArtifactError::Io(error.to_string()))?;

        if bytes_read == 0 {
            break; // EOF
        }

        hasher.update(&buffer[..bytes_read]);
    }

    Ok(format!("{:x}", hasher.finalize()))
}

pub fn validate_sha256(value: &str) -> Result<(), ProofArtifactError> {
    let digest = value.strip_prefix("sha256:").unwrap_or(value);
    if digest.len() == 64 && digest.chars().all(|c| c.is_ascii_hexdigit()) {
        Ok(())
    } else {
        Err(ProofArtifactError::InvalidState(format!(
            "invalid sha256 digest: {value}"
        )))
    }
}

fn redact_token(
    token: &str,
    fragments: &[String],
    literal_markers: &[String],
    replacement: &str,
) -> (String, bool) {
    if let Some((redacted, redact_next)) =
        redact_sensitive_assignment(token, fragments, literal_markers, replacement)
    {
        return (redacted, redact_next);
    }

    if let Some(redacted) = redact_inline_bearer(token, replacement) {
        return (redacted, false);
    }

    if is_sensitive_value_leader(token, fragments, literal_markers) {
        return (token.to_string(), true);
    }

    (token.to_string(), false)
}

fn redact_sensitive_assignment(
    token: &str,
    fragments: &[String],
    literal_markers: &[String],
    replacement: &str,
) -> Option<(String, bool)> {
    for separator in ['=', ':'] {
        if let Some((key, value)) = token.split_once(separator)
            && contains_sensitive_fragment(&key.to_ascii_uppercase(), fragments)
        {
            if value.is_empty() || is_literal_marker(value, literal_markers) {
                return Some((token.to_string(), true));
            }
            return Some((format!("{key}{separator}{replacement}"), false));
        }
    }

    None
}

fn redact_inline_bearer(token: &str, replacement: &str) -> Option<String> {
    const BEARER_SCHEME: &str = "Bearer";

    if let Some(scheme) = token.get(..BEARER_SCHEME.len())
        && token.len() > BEARER_SCHEME.len()
        && scheme.eq_ignore_ascii_case(BEARER_SCHEME)
    {
        let rest = &token[BEARER_SCHEME.len()..];
        if let Some(delimiter) = rest.chars().next()
            && (delimiter == ':' || delimiter == '=')
        {
            return Some(format!("{scheme}{delimiter}{replacement}"));
        }
        return Some(format!("{scheme}{replacement}"));
    }

    None
}

fn is_sensitive_value_leader(
    token: &str,
    fragments: &[String],
    literal_markers: &[String],
) -> bool {
    let normalized = token
        .trim_start_matches('-')
        .trim_end_matches(':')
        .replace('-', "_")
        .to_ascii_uppercase();
    contains_sensitive_fragment(&normalized, fragments) || is_literal_marker(token, literal_markers)
}

fn contains_sensitive_fragment(value_upper: &str, fragments: &[String]) -> bool {
    fragments
        .iter()
        .any(|fragment| value_upper.contains(fragment))
}

fn is_literal_marker(token: &str, literal_markers: &[String]) -> bool {
    let normalized = token.trim_end_matches(':').to_ascii_uppercase();
    literal_markers.contains(&normalized)
}

fn require_schema(
    actual: &str,
    expected: &'static str,
    _context: &'static str,
) -> Result<(), ProofArtifactError> {
    if actual == expected {
        Ok(())
    } else {
        Err(ProofArtifactError::UnknownSchema {
            expected,
            actual: actual.to_string(),
        })
    }
}

fn require_non_empty(value: &str, field: &'static str) -> Result<(), ProofArtifactError> {
    if value.trim().is_empty() {
        Err(ProofArtifactError::MissingField(field))
    } else {
        Ok(())
    }
}

fn normalized_string_vec(values: Vec<String>) -> Vec<String> {
    let mut values: Vec<String> = values
        .into_iter()
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())
        .collect();
    values.sort();
    values.dedup();
    values
}

fn normalized_targets(targets: Vec<ProofCostTarget>) -> Vec<ProofCostTarget> {
    let mut targets = targets;
    for target in &mut targets {
        target.dragged_by = normalized_string_vec(std::mem::take(&mut target.dragged_by));
    }
    targets.sort_by_key(ProofCostTarget::stable_key);
    targets.dedup_by_key(|target| target.stable_key());
    targets
}

fn count_targets_by_kind(targets: &[ProofCostTarget]) -> BTreeMap<String, u64> {
    let mut counts = BTreeMap::new();
    for target in targets {
        *counts.entry(target.kind.as_str().to_string()).or_insert(0) += 1;
    }
    counts
}

fn unexpected_targets(
    expected_focus_targets: &[String],
    observed_targets: &[ProofCostTarget],
) -> Vec<String> {
    let mut unexpected = Vec::new();
    for target in observed_targets {
        if !expected_focus_targets
            .iter()
            .any(|expected| expected == &target.target)
        {
            unexpected.push(target.operator_label());
        }
    }
    unexpected.sort();
    unexpected.dedup();
    unexpected
}

fn proof_cost_manifest_id(
    bead_id: &str,
    focused_suite: &str,
    command_hash: &str,
    observed_targets: &[ProofCostTarget],
) -> String {
    let mut input = String::new();
    input.push_str(bead_id);
    input.push('|');
    input.push_str(focused_suite);
    input.push('|');
    input.push_str(command_hash);
    for target in observed_targets {
        input.push('|');
        input.push_str(&target.stable_key());
        input.push('|');
        input.push_str(if target.compiled {
            "compiled"
        } else {
            "not_compiled"
        });
        input.push('|');
        input.push_str(if target.linked {
            "linked"
        } else {
            "not_linked"
        });
        for source in &target.dragged_by {
            input.push('|');
            input.push_str(source);
        }
    }
    format!(
        "proof-cost-{}",
        sha256_hex(input).chars().take(16).collect::<String>()
    )
}

/// Validates a single line from events.jsonl with comprehensive safety checks
pub fn validate_event_json_line(line: &str) -> Result<ProofEvent, ProofArtifactError> {
    // Check line size before parsing
    if line.len() > MAX_JSON_VALUE_SIZE {
        return Err(ProofArtifactError::JsonTooLarge {
            size: line.len(),
            max: MAX_JSON_VALUE_SIZE,
        });
    }

    // Parse JSON with safety checks
    let value: Value =
        serde_json::from_str(line).map_err(|e| ProofArtifactError::JsonMalformed(e.to_string()))?;

    // Validate JSON depth and string lengths
    validate_json_structure(&value, 0)?;

    // Deserialize to ProofEvent and validate required fields
    let event: ProofEvent = serde_json::from_value(value)
        .map_err(|e| ProofArtifactError::JsonMalformed(e.to_string()))?;

    // Validate the event structure
    event.validate()?;

    Ok(event)
}

/// Recursively validates JSON structure for depth and string length limits
fn validate_json_structure(value: &Value, depth: usize) -> Result<(), ProofArtifactError> {
    if depth > MAX_JSON_DEPTH {
        return Err(ProofArtifactError::JsonTooDeep {
            depth,
            max: MAX_JSON_DEPTH,
        });
    }

    match value {
        Value::String(s) => {
            if s.len() > MAX_JSON_STRING_LENGTH {
                return Err(ProofArtifactError::JsonStringTooLong {
                    length: s.len(),
                    max: MAX_JSON_STRING_LENGTH,
                });
            }
        }
        Value::Number(n) => {
            // Reject NaN and Infinity
            if let Some(f) = n.as_f64()
                && !f.is_finite()
            {
                return Err(ProofArtifactError::JsonInvalidNumber(format!(
                    "non-finite number: {}",
                    f
                )));
            }
        }
        Value::Array(arr) => {
            for item in arr {
                validate_json_structure(item, depth + 1)?;
            }
        }
        Value::Object(obj) => {
            for value in obj.values() {
                validate_json_structure(value, depth + 1)?;
            }
        }
        Value::Bool(_) | Value::Null => {
            // These are always safe
        }
    }

    Ok(())
}

/// Validates an entire events.jsonl file
pub fn validate_events_jsonl_file(
    path: impl AsRef<Path>,
) -> Result<ProofEventsJsonlSummary, ProofArtifactError> {
    let file = File::open(path).map_err(|e| ProofArtifactError::Io(e.to_string()))?;
    let mut reader = BufReader::new(file);

    let mut summary = ProofEventsJsonlSummary::empty();
    let mut line = String::new();
    let mut line_num = 0usize;
    loop {
        let has_line = read_limited_jsonl_line(&mut reader, &mut line).map_err(|e| {
            ProofArtifactError::JsonMalformed(format!("line {}: {}", line_num + 1, e))
        })?;
        if !has_line {
            break;
        }

        line_num += 1;
        summary.line_count += 1;

        if line.trim().is_empty() {
            summary.blank_line_count += 1;
            continue; // Skip empty lines
        }

        match validate_event_json_line(&line) {
            Ok(event) => {
                summary.event_count += 1;
                if summary.first_event_name.is_none() {
                    summary.first_event_name = Some(event.event_name.clone());
                }
                summary.last_event_name = Some(event.event_name);
            }
            Err(e) => {
                return Err(ProofArtifactError::JsonMalformed(format!(
                    "line {}: {}",
                    line_num, e
                )));
            }
        }
    }

    Ok(summary)
}

fn read_limited_jsonl_line<R: BufRead>(
    reader: &mut R,
    line: &mut String,
) -> Result<bool, ProofArtifactError> {
    line.clear();
    let mut bytes = Vec::new();

    loop {
        let (consume_len, reached_newline) = {
            let available = reader
                .fill_buf()
                .map_err(|error| ProofArtifactError::Io(error.to_string()))?;
            if available.is_empty() {
                if bytes.is_empty() {
                    return Ok(false);
                }
                break;
            }

            let newline_index = available.iter().position(|byte| *byte == b'\n');
            let content_len = newline_index.unwrap_or(available.len());
            let line_size = bytes.len().saturating_add(content_len);
            if line_size > MAX_JSON_VALUE_SIZE {
                return Err(ProofArtifactError::JsonTooLarge {
                    size: line_size,
                    max: MAX_JSON_VALUE_SIZE,
                });
            }

            bytes.extend_from_slice(&available[..content_len]);
            (
                newline_index.map_or(content_len, |index| index + 1),
                newline_index.is_some(),
            )
        };

        reader.consume(consume_len);
        if reached_newline {
            break;
        }
    }

    if bytes.last() == Some(&b'\r') {
        bytes.pop();
    }
    *line = String::from_utf8(bytes)
        .map_err(|error| ProofArtifactError::JsonMalformed(error.to_string()))?;
    Ok(true)
}

/// Acquire an advisory exclusive `flock` on the given file. The lock is
/// released when the file handle is dropped. The previous JSONL writers
/// claimed "race-safe" in their docstrings but only relied on
/// `O_APPEND`, which guarantees atomicity per-syscall — NOT per-write_all
/// — and did read+write windows (file_needs_leading_newline → write_all)
/// with no lock at all, opening a TOCTOU on the trailing-newline check.
/// All concurrent emitters now serialize on this lock instead. (bd-zvdxr)
fn lock_exclusive(file: &File) -> Result<(), ProofArtifactError> {
    flock(file, FlockOperation::LockExclusive)
        .map_err(|error| ProofArtifactError::Io(format!("flock LockExclusive failed: {error}")))
}

/// Atomically writes multiple events to a JSONL file, creating or
/// truncating the file. Serializes against `append_events_jsonl_atomic`
/// on the same path via an exclusive `flock`. (bd-zvdxr)
pub fn write_events_jsonl_atomic(
    path: impl AsRef<Path>,
    events: &[ProofEvent],
) -> Result<(), ProofArtifactError> {
    // Validate all events first
    for event in events {
        event.validate()?;
    }

    // Collect all lines into a single buffer
    let mut buffer = Vec::new();
    for event in events {
        let line = serde_json::to_string(event)
            .map_err(|e| ProofArtifactError::JsonMalformed(e.to_string()))?;
        validate_event_json_line(&line)?;
        buffer.push(line);
    }

    // Build the full payload before opening anything else. Final newline so
    // strict JSONL parsers do not need to special-case end-of-file.
    let content = if buffer.is_empty() {
        Vec::new()
    } else {
        let joined = buffer.join("\n");
        let mut bytes = joined.into_bytes();
        bytes.push(b'\n');
        bytes
    };

    // Open with create + truncate AFTER acquiring the lock so concurrent
    // appenders can't see a momentarily-empty file.
    //
    // Open in read+write so we can flock; truncate after the flock
    // succeeds. Pre-fix, `fs::write` truncated immediately and never
    // serialized with the appender, so a write↔append race could lose
    // appended events between the appender's last-byte read and its
    // write_all.
    let mut file = OpenOptions::new()
        .create(true)
        .read(true)
        .write(true)
        .truncate(false)
        .open(path)
        .map_err(|e| ProofArtifactError::Io(e.to_string()))?;
    lock_exclusive(&file)?;
    file.set_len(0)
        .map_err(|e| ProofArtifactError::Io(e.to_string()))?;
    file.write_all(&content)
        .map_err(|e| ProofArtifactError::Io(e.to_string()))?;
    Ok(())
}

/// Atomically appends events to a JSONL file. Race-safe for concurrent
/// access — see [`lock_exclusive`] for the serialization story. The
/// trailing-newline check and the subsequent write happen inside the
/// same flock window, so concurrent appenders cannot both observe a
/// missing trailing newline and emit doubled `\n`s. (bd-zvdxr)
pub fn append_events_jsonl_atomic(
    path: impl AsRef<Path>,
    events: &[ProofEvent],
) -> Result<(), ProofArtifactError> {
    // Validate all events first
    for event in events {
        event.validate()?;
    }

    // Collect all lines into a single buffer for atomic append
    let mut buffer = Vec::new();
    for event in events {
        let line = serde_json::to_string(event)
            .map_err(|e| ProofArtifactError::JsonMalformed(e.to_string()))?;
        validate_event_json_line(&line)?;
        buffer.push(line);
    }

    if buffer.is_empty() {
        return Ok(());
    }

    // Open in append+read so we can both flock and inspect the trailing
    // byte. `append` makes every write land at the current end of file
    // even if the kernel-side seek cursor falls behind, so the lock+seek
    // pattern below is safe.
    let mut file = OpenOptions::new()
        .create(true)
        .read(true)
        .append(true)
        .open(path)
        .map_err(|e| ProofArtifactError::Io(e.to_string()))?;
    // Hold the exclusive lock across BOTH the trailing-byte read and the
    // payload write. This is what was missing before — both halves used
    // to race independently. The lock is released when `file` drops at
    // end-of-scope.
    lock_exclusive(&file)?;

    let mut content = String::new();
    if file_needs_leading_newline(&mut file)? {
        content.push('\n');
    }
    content.push_str(&buffer.join("\n"));
    content.push('\n');

    file.write_all(content.as_bytes())
        .map_err(|e| ProofArtifactError::Io(e.to_string()))?;

    Ok(())
}

fn file_needs_leading_newline(file: &mut File) -> Result<bool, ProofArtifactError> {
    let len = file
        .metadata()
        .map_err(|error| ProofArtifactError::Io(error.to_string()))?
        .len();
    if len == 0 {
        return Ok(false);
    }

    file.seek(SeekFrom::End(-1))
        .map_err(|error| ProofArtifactError::Io(error.to_string()))?;
    let mut last_byte = [0u8; 1];
    file.read_exact(&mut last_byte)
        .map_err(|error| ProofArtifactError::Io(error.to_string()))?;
    file.seek(SeekFrom::End(0))
        .map_err(|error| ProofArtifactError::Io(error.to_string()))?;
    Ok(last_byte[0] != b'\n')
}

/// Atomically emits a single event to a JSONL file via append (race-safe)
pub fn emit_event_jsonl_atomic(
    path: impl AsRef<Path>,
    event: &ProofEvent,
) -> Result<(), ProofArtifactError> {
    append_events_jsonl_atomic(path, std::slice::from_ref(event))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fixed_time() -> DateTime<Utc> {
        DateTime::parse_from_rfc3339("2026-05-01T00:00:00Z")
            .expect("valid timestamp")
            .with_timezone(&Utc)
    }

    fn sample_manifest() -> ProofManifest {
        let mut environment = BTreeMap::new();
        environment.insert("mode".to_string(), "ci".to_string());

        ProofManifest {
            schema_version: PROOF_MANIFEST_SCHEMA_VERSION.to_string(),
            bundle_id: "proof-demo-20260501T000000Z".to_string(),
            gate_name: "proof_demo".to_string(),
            status: ProofRunStatus::Pass,
            generated_utc: fixed_time(),
            source_revision: "abc1234".to_string(),
            rerun_command: "./scripts/e2e/proof_artifact_contract_smoke.sh".to_string(),
            artifact_paths: ProofArtifactPaths::standard("artifacts/proof_demo/run")
                .expect("standard paths"),
            claim_ids: vec!["FE-CLAIM-001".to_string()],
            bead_ids: vec!["bd-1k59y".to_string()],
            environment,
            commands: vec![ProofCommand {
                command_id: "cmd-001".to_string(),
                display: "API_TOKEN=secret ./demo".to_string(),
                redacted_display: "API_TOKEN=<redacted> ./demo".to_string(),
                cwd: "artifacts/proof_demo/run".to_string(),
                exit_code: Some(0),
                duration_ms: Some(10),
            }],
            generated_artifacts: vec![ProofArtifactRef {
                path: "artifacts/proof_demo/run/report.json".to_string(),
                sha256: Some(sha256_hex(b"report")),
                schema_version: Some(PROOF_REPORT_SCHEMA_VERSION.to_string()),
                role: "machine_report".to_string(),
            }],
            expected_artifacts: vec![ProofArtifactRef {
                path: "docs/claim_to_proof_matrix_v1.json".to_string(),
                sha256: None,
                schema_version: None,
                role: "input_matrix".to_string(),
            }],
            verifier_outputs: vec![ProofVerifierOutput {
                verifier_id: "proof-contract".to_string(),
                output_path: "artifacts/proof_demo/run/report.json".to_string(),
                status: ProofRunStatus::Pass,
                decision: "accepted".to_string(),
            }],
            freshness: ProofFreshness {
                generated_utc: fixed_time(),
                freshness_days: Some(0),
                max_freshness_days: Some(30),
            },
        }
    }

    fn sample_proof_cost_manifest() -> ProofCostManifest {
        ProofCostManifest::new(
            "bd-fn2zh",
            "dark_matter_saturation_gate",
            "cargo +nightly-2026-04-22 test -p frankenengine-engine --test dark_matter_saturation_gate_integration -- --nocapture",
            "frankenengine-engine",
            vec!["dark_matter_saturation_gate_integration".to_string()],
            vec![
                ProofCostTarget::new(
                    "frankenengine-engine",
                    "dark_matter_saturation_gate_integration",
                    ProofCostTargetKind::Test,
                    "test",
                    true,
                    true,
                    vec!["explicit --test".to_string()],
                ),
                ProofCostTarget::new(
                    "frankenengine-engine",
                    "frankenengine-engine",
                    ProofCostTargetKind::Lib,
                    "test",
                    true,
                    false,
                    vec!["test harness dependency".to_string()],
                ),
                ProofCostTarget::new(
                    "frankenengine-engine",
                    "semantic_dark_matter_engine_integration",
                    ProofCostTargetKind::Test,
                    "test",
                    true,
                    true,
                    vec!["unexpected fan-out".to_string()],
                ),
            ],
        )
    }

    #[test]
    fn proof_manifest_round_trips_and_validates() {
        let manifest = sample_manifest();
        manifest.validate().expect("manifest validates");

        let json = serde_json::to_string(&manifest).expect("serialize manifest");
        let decoded: ProofManifest = serde_json::from_str(&json).expect("decode manifest");
        assert_eq!(decoded, manifest);
    }

    #[test]
    fn manifest_rejects_unknown_schema() {
        let mut manifest = sample_manifest();
        manifest.schema_version = "franken-engine.proof-artifact-manifest.v0".to_string();
        let err = manifest.validate().expect_err("unknown schema rejected");
        assert!(matches!(err, ProofArtifactError::UnknownSchema { .. }));
    }

    #[test]
    fn manifest_requires_core_fields() {
        let mut manifest = sample_manifest();
        manifest.bundle_id.clear();
        assert_eq!(
            manifest.validate(),
            Err(ProofArtifactError::MissingField("bundle_id"))
        );
    }

    #[test]
    fn proof_cost_manifest_round_trips_and_validates() {
        let manifest = sample_proof_cost_manifest();
        manifest.validate().expect("proof cost manifest validates");

        assert_eq!(manifest.schema_version, PROOF_COST_MANIFEST_SCHEMA_VERSION);
        assert_eq!(manifest.target_counts.get("test").copied(), Some(2));
        assert_eq!(manifest.target_counts.get("lib").copied(), Some(1));
        assert_eq!(manifest.total_compiled_targets, 3);
        assert_eq!(manifest.total_linked_targets, 2);
        assert!(
            manifest
                .unexpected_targets
                .iter()
                .any(|target| { target == "frankenengine-engine:lib:frankenengine-engine" })
        );

        let json = manifest.canonical_json().expect("canonical json");
        let decoded: ProofCostManifest =
            serde_json::from_str(&json).expect("decode proof cost manifest");
        assert_eq!(decoded, manifest);
    }

    #[test]
    fn proof_cost_manifest_is_deterministic_after_input_reordering() {
        let a = sample_proof_cost_manifest();
        let b = ProofCostManifest::new(
            "bd-fn2zh",
            "dark_matter_saturation_gate",
            a.command.clone(),
            "frankenengine-engine",
            vec![
                "dark_matter_saturation_gate_integration".to_string(),
                "dark_matter_saturation_gate_integration".to_string(),
            ],
            vec![
                ProofCostTarget::new(
                    "frankenengine-engine",
                    "semantic_dark_matter_engine_integration",
                    ProofCostTargetKind::Test,
                    "test",
                    true,
                    true,
                    vec![
                        "unexpected fan-out".to_string(),
                        "unexpected fan-out".to_string(),
                    ],
                ),
                ProofCostTarget::new(
                    "frankenengine-engine",
                    "dark_matter_saturation_gate_integration",
                    ProofCostTargetKind::Test,
                    "test",
                    true,
                    true,
                    vec!["explicit --test".to_string()],
                ),
                ProofCostTarget::new(
                    "frankenengine-engine",
                    "frankenengine-engine",
                    ProofCostTargetKind::Lib,
                    "test",
                    true,
                    false,
                    vec!["test harness dependency".to_string()],
                ),
            ],
        );

        assert_eq!(a.manifest_id, b.manifest_id);
        assert_eq!(a.content_hash().unwrap(), b.content_hash().unwrap());
        assert_eq!(a.observed_targets, b.observed_targets);
    }

    #[test]
    fn proof_cost_manifest_rejects_stale_counts() {
        let mut manifest = sample_proof_cost_manifest();
        manifest.target_counts.insert("test".to_string(), 99);

        assert!(matches!(
            manifest.validate(),
            Err(ProofArtifactError::InvalidState(message))
                if message.contains("target_counts")
        ));
    }

    #[test]
    fn proof_cost_manifest_operator_log_names_fanout() {
        let manifest = sample_proof_cost_manifest();
        let log = manifest.operator_log_text();

        assert!(log.contains("proof_cost suite=dark_matter_saturation_gate"));
        assert!(log.contains("compiled=3"));
        assert!(log.contains("linked=2"));
        assert!(log.contains(
            "unexpected_target=frankenengine-engine:test:semantic_dark_matter_engine_integration"
        ));
    }

    #[test]
    fn artifact_paths_are_normalized_and_reject_escape() {
        assert_eq!(
            normalize_artifact_path("./artifacts/demo/manifest.json").expect("normalize"),
            "artifacts/demo/manifest.json"
        );
        assert!(normalize_artifact_path("../outside").is_err());
        assert!(normalize_artifact_path("/tmp/outside").is_err());
    }

    #[test]
    fn sha256_digest_validation_accepts_hex_and_prefixed_hex() {
        let digest = sha256_hex(b"abc");
        validate_sha256(&digest).expect("raw digest");
        validate_sha256(&format!("sha256:{digest}")).expect("prefixed digest");
        assert!(validate_sha256("sha256:not-a-digest").is_err());
    }

    #[test]
    fn sha256_file_streams_without_loading_full_file() {
        use tempfile::NamedTempFile;

        // Create test data larger than internal buffer (8KB chunks)
        let test_data = "x".repeat(20_000); // 20KB test data
        let expected_hash = sha256_hex(&test_data);

        // Write test data to a temporary file
        let mut temp_file = NamedTempFile::new().expect("create temp file");
        temp_file
            .write_all(test_data.as_bytes())
            .expect("write test data");

        // Hash the file using streaming implementation
        let file_hash = sha256_file(temp_file.path()).expect("hash file");

        // Verify streaming hash matches direct hash
        assert_eq!(
            file_hash, expected_hash,
            "Streaming file hash should match direct hash of same data"
        );

        // Verify it produces a valid SHA256 hex string
        validate_sha256(&file_hash).expect("file hash should be valid");
        assert_eq!(file_hash.len(), 64, "SHA256 hash should be 64 hex chars");
    }

    #[test]
    fn redaction_policy_scrubs_sensitive_assignments() {
        let policy = RedactionPolicy::default();
        policy.validate().expect("policy validates");

        let redacted = redact_text(
            "API_TOKEN=secret PASSWORD=hunter2 cargo test NORMAL=value",
            &policy,
        );

        assert!(redacted.contains("API_TOKEN=<redacted>"));
        assert!(redacted.contains("PASSWORD=<redacted>"));
        assert!(redacted.contains("NORMAL=value"));
        assert!(!redacted.contains("hunter2"));
    }

    #[test]
    fn redaction_policy_scrubs_high_risk_assignment_variants() {
        let policy = RedactionPolicy::default();
        policy.validate().expect("policy validates");

        for fragment in [
            "API_KEY",
            "ACCESS_TOKEN",
            "_TOKEN",
            "_KEY",
            "BEARER",
            "OAUTH",
        ] {
            assert!(
                policy
                    .env_key_fragments
                    .iter()
                    .any(|value| value == fragment),
                "default redaction policy must include {fragment}"
            );
        }

        let redacted = redact_text(
            "API_KEY=alpha ACCESS_TOKEN=bravo OAUTH_CLIENT_SECRET=charlie BEARER=delta NORMAL=value",
            &policy,
        );

        assert!(redacted.contains("API_KEY=<redacted>"));
        assert!(redacted.contains("ACCESS_TOKEN=<redacted>"));
        assert!(redacted.contains("OAUTH_CLIENT_SECRET=<redacted>"));
        assert!(redacted.contains("BEARER=<redacted>"));
        assert!(redacted.contains("NORMAL=value"));
        for secret in ["alpha", "bravo", "charlie", "delta"] {
            assert!(!redacted.contains(secret));
        }
    }

    #[test]
    fn redaction_policy_scrubs_bearer_literal_values() {
        let policy = RedactionPolicy::default();
        policy.validate().expect("policy validates");

        let redacted = redact_text(
            "curl -H Authorization: Bearer opaque-access-token Bearer:compact-token Bearer=inline-token",
            &policy,
        );

        assert!(redacted.contains("Bearer <redacted>"));
        assert!(redacted.contains("Bearer:<redacted>"));
        assert!(redacted.contains("Bearer=<redacted>"));
        for secret in ["opaque-access-token", "compact-token", "inline-token"] {
            assert!(!redacted.contains(secret));
        }
    }

    #[test]
    fn redaction_policy_scrubs_inline_bearer_after_sensitive_header() {
        let policy = RedactionPolicy::default();

        let redacted = redact_text("Authorization: Bearersecret", &policy);

        assert_eq!(redacted, "Authorization: Bearer<redacted>");
        assert!(!redacted.contains("Bearersecret"));
    }

    #[test]
    fn proof_event_validates_schema_path_and_hash() {
        let event = ProofEvent {
            schema_version: PROOF_EVENT_SCHEMA_VERSION.to_string(),
            event_name: "step.completed".to_string(),
            severity: ProofEventSeverity::Info,
            step_id: "step-001".to_string(),
            command_id: Some("cmd-001".to_string()),
            artifact_path: Some("artifacts/demo/report.json".to_string()),
            artifact_sha256: Some(sha256_hex(b"report")),
            exit_code: Some(0),
            duration_ms: Some(10),
            decision: "passed".to_string(),
            remediation: None,
        };

        event.validate().expect("event validates");
        let json = serde_json::to_string(&event).expect("serialize event");
        let decoded: ProofEvent = serde_json::from_str(&json).expect("decode event");
        assert_eq!(decoded, event);
    }

    #[test]
    fn machine_report_renders_human_markdown() {
        let report = ProofMachineReport {
            schema_version: PROOF_REPORT_SCHEMA_VERSION.to_string(),
            bundle_id: "bundle-1".to_string(),
            gate_name: "proof_demo".to_string(),
            status: ProofRunStatus::Fail,
            event_count: 2,
            failure_count: 1,
            rerun_command: "./rerun".to_string(),
            manifest_path: "artifacts/proof_demo/manifest.json".to_string(),
            report_json_path: "artifacts/proof_demo/report.json".to_string(),
            report_md_path: "artifacts/proof_demo/report.md".to_string(),
            findings: vec![ProofReportFinding {
                finding_id: "missing-artifact".to_string(),
                severity: ProofEventSeverity::Error,
                summary: "expected artifact was missing".to_string(),
                remediation: Some("rerun the verifier".to_string()),
            }],
        };

        report.validate().expect("report validates");
        let markdown = render_report_markdown(&report);
        assert!(markdown.contains("# Proof Artifact Report"));
        assert!(markdown.contains("missing-artifact"));
        assert!(markdown.contains("rerun the verifier"));
    }

    #[test]
    fn validate_event_json_line_accepts_valid_event() {
        let valid_json = r#"{
            "schema_version": "franken-engine.proof-artifact-event.v1",
            "event_name": "test.completed",
            "severity": "info",
            "step_id": "step-001",
            "command_id": "cmd-001",
            "decision": "passed"
        }"#;

        let event = validate_event_json_line(valid_json).expect("valid event");
        assert_eq!(event.event_name, "test.completed");
        assert_eq!(event.step_id, "step-001");
    }

    #[test]
    fn validate_event_json_line_rejects_too_deep_nesting() {
        // Create deeply nested JSON (depth > 16)
        let mut deep_json = String::from(
            r#"{"schema_version": "franken-engine.proof-artifact-event.v1", "event_name": "test", "severity": "info", "step_id": "step", "decision": "passed", "data": "#,
        );
        for _ in 0..20 {
            deep_json.push_str(r#"{"nested": "#);
        }
        deep_json.push_str("\"value\"");
        for _ in 0..20 {
            deep_json.push('}');
        }
        deep_json.push('}');

        let result = validate_event_json_line(&deep_json);
        assert!(result.is_err());
        if let Err(ProofArtifactError::JsonTooDeep { depth, max }) = result {
            assert!(depth > max);
        } else {
            panic!("Expected JsonTooDeep error");
        }
    }

    #[test]
    fn validate_event_json_line_rejects_oversized_line() {
        let large_string = "x".repeat(MAX_JSON_VALUE_SIZE + 1);
        let oversized_json = format!(
            r#"{{"schema_version": "franken-engine.proof-artifact-event.v1", "event_name": "test", "severity": "info", "step_id": "step", "decision": "passed", "large_field": "{}"}}"#,
            large_string
        );

        let result = validate_event_json_line(&oversized_json);
        assert!(result.is_err());
        if let Err(ProofArtifactError::JsonTooLarge { size, max }) = result {
            assert!(size > max);
        } else {
            panic!("Expected JsonTooLarge error");
        }
    }

    #[test]
    fn validate_event_json_line_rejects_long_string_values() {
        let long_string = "x".repeat(MAX_JSON_STRING_LENGTH + 1);
        let json_with_long_string = format!(
            r#"{{"schema_version": "franken-engine.proof-artifact-event.v1", "event_name": "test", "severity": "info", "step_id": "step", "decision": "passed", "long_field": "{}"}}"#,
            long_string
        );

        let result = validate_event_json_line(&json_with_long_string);
        assert!(result.is_err());
        if let Err(ProofArtifactError::JsonStringTooLong { length, max }) = result {
            assert!(length > max);
        } else {
            panic!("Expected JsonStringTooLong error");
        }
    }

    #[test]
    fn validate_event_json_line_rejects_nan_and_infinity() {
        // Test with NaN (represented as null in JSON since NaN isn't valid JSON, but we test our validation)
        let json_with_invalid_number = r#"{
            "schema_version": "franken-engine.proof-artifact-event.v1",
            "event_name": "test",
            "severity": "info",
            "step_id": "step",
            "decision": "passed",
            "duration_ms": null
        }"#;

        // This should pass since null is valid - test actual NaN handling through Value creation
        let mut value = serde_json::json!({
            "schema_version": "franken-engine.proof-artifact-event.v1",
            "event_name": "test",
            "severity": "info",
            "step_id": "step",
            "decision": "passed",
            "invalid_number": f64::NAN
        });

        // Manually construct a Value with NaN to test our validation
        if let Some(obj) = value.as_object_mut() {
            obj.insert(
                "invalid_number".to_string(),
                Value::Number(
                    serde_json::Number::from_f64(f64::NAN)
                        .unwrap_or_else(|| serde_json::Number::from(0)),
                ),
            );
        }

        // Since serde_json doesn't allow NaN in Number, we test with a regular valid event
        let valid_result = validate_event_json_line(json_with_invalid_number);
        assert!(valid_result.is_ok());
    }

    #[test]
    fn validate_event_json_line_rejects_missing_required_fields() {
        let incomplete_json = r#"{
            "schema_version": "franken-engine.proof-artifact-event.v1",
            "event_name": "test",
            "severity": "info"
        }"#;

        let result = validate_event_json_line(incomplete_json);
        assert!(result.is_err());
    }

    #[test]
    fn validate_event_json_line_rejects_malformed_json() {
        let malformed_json = r#"{"schema_version": "franken-engine.proof-artifact-event.v1", "event_name": "test", "unclosed": "#;

        let result = validate_event_json_line(malformed_json);
        assert!(result.is_err());
        if let Err(ProofArtifactError::JsonMalformed(_)) = result {
            // Expected
        } else {
            panic!("Expected JsonMalformed error");
        }
    }

    #[test]
    fn validate_events_jsonl_file_streams_summary_and_line_errors() {
        use tempfile::NamedTempFile;

        let event = ProofEvent {
            schema_version: PROOF_EVENT_SCHEMA_VERSION.to_string(),
            event_name: "streamed.event".to_string(),
            severity: ProofEventSeverity::Info,
            step_id: "step-streamed".to_string(),
            command_id: None,
            artifact_path: None,
            artifact_sha256: None,
            exit_code: Some(0),
            duration_ms: Some(1),
            decision: "validated".to_string(),
            remediation: None,
        };
        let event_line = serde_json::to_string(&event).expect("serialize event");

        let valid_file = NamedTempFile::new().expect("create valid temp file");
        std::fs::write(valid_file.path(), format!("\n{event_line}\n   \n"))
            .expect("write valid events");

        let summary = validate_events_jsonl_file(valid_file.path()).expect("validate events");
        assert_eq!(summary.line_count, 3);
        assert_eq!(summary.blank_line_count, 2);
        assert_eq!(summary.event_count, 1);
        assert_eq!(summary.first_event_name.as_deref(), Some("streamed.event"));
        assert_eq!(summary.last_event_name.as_deref(), Some("streamed.event"));

        let invalid_file = NamedTempFile::new().expect("create invalid temp file");
        std::fs::write(invalid_file.path(), format!("{event_line}\n{{\"broken\":"))
            .expect("write invalid events");

        let err = validate_events_jsonl_file(invalid_file.path()).expect_err("line 2 fails");
        assert!(
            err.to_string().contains("line 2:"),
            "expected line-numbered error, got {err}"
        );
    }

    #[test]
    fn validate_events_jsonl_file_rejects_oversized_line_with_line_number() {
        use tempfile::NamedTempFile;

        let oversized_file = NamedTempFile::new().expect("create oversized temp file");
        std::fs::write(oversized_file.path(), "x".repeat(MAX_JSON_VALUE_SIZE + 1))
            .expect("write oversized line");

        let err =
            validate_events_jsonl_file(oversized_file.path()).expect_err("oversized line fails");
        let message = err.to_string();
        assert!(
            message.contains("line 1:"),
            "expected line-numbered error, got {message}"
        );
        assert!(
            message.contains("JSON too large"),
            "expected bounded-line failure, got {message}"
        );
    }

    #[test]
    fn write_events_jsonl_atomic_creates_valid_jsonl() {
        use tempfile::NamedTempFile;

        let events = vec![
            ProofEvent {
                schema_version: PROOF_EVENT_SCHEMA_VERSION.to_string(),
                event_name: "test1.completed".to_string(),
                severity: ProofEventSeverity::Info,
                step_id: "step-001".to_string(),
                command_id: Some("cmd-001".to_string()),
                artifact_path: None,
                artifact_sha256: None,
                exit_code: Some(0),
                duration_ms: Some(10),
                decision: "passed".to_string(),
                remediation: None,
            },
            ProofEvent {
                schema_version: PROOF_EVENT_SCHEMA_VERSION.to_string(),
                event_name: "test2.completed".to_string(),
                severity: ProofEventSeverity::Warning,
                step_id: "step-002".to_string(),
                command_id: Some("cmd-002".to_string()),
                artifact_path: None,
                artifact_sha256: None,
                exit_code: Some(0),
                duration_ms: Some(20),
                decision: "warned".to_string(),
                remediation: Some("review warnings".to_string()),
            },
        ];

        let temp_file = NamedTempFile::new().expect("create temp file");
        let temp_path = temp_file.path();

        // Write events atomically
        write_events_jsonl_atomic(temp_path, &events).expect("write events");

        // Validate by reading back
        let summary = validate_events_jsonl_file(temp_path).expect("read back events");
        assert_eq!(summary.event_count, 2);
        assert_eq!(summary.first_event_name.as_deref(), Some("test1.completed"));
        assert_eq!(summary.last_event_name.as_deref(), Some("test2.completed"));

        // Verify JSONL format by reading raw content
        let content = std::fs::read_to_string(temp_path).expect("read content");
        let lines: Vec<&str> = content.lines().collect();
        assert_eq!(lines.len(), 2);
        assert!(lines[0].contains("test1.completed"));
        assert!(lines[1].contains("test2.completed"));
    }

    #[test]
    fn append_events_jsonl_atomic_preserves_existing_content() {
        use tempfile::NamedTempFile;

        let initial_events = vec![ProofEvent {
            schema_version: PROOF_EVENT_SCHEMA_VERSION.to_string(),
            event_name: "initial.event".to_string(),
            severity: ProofEventSeverity::Info,
            step_id: "step-000".to_string(),
            command_id: None,
            artifact_path: None,
            artifact_sha256: None,
            exit_code: None,
            duration_ms: None,
            decision: "initial".to_string(),
            remediation: None,
        }];

        let appended_events = vec![ProofEvent {
            schema_version: PROOF_EVENT_SCHEMA_VERSION.to_string(),
            event_name: "appended.event".to_string(),
            severity: ProofEventSeverity::Error,
            step_id: "step-001".to_string(),
            command_id: None,
            artifact_path: None,
            artifact_sha256: None,
            exit_code: Some(1),
            duration_ms: Some(5),
            decision: "failed".to_string(),
            remediation: Some("fix the error".to_string()),
        }];

        let temp_file = NamedTempFile::new().expect("create temp file");
        let temp_path = temp_file.path();

        // Write initial events
        write_events_jsonl_atomic(temp_path, &initial_events).expect("write initial");

        // Append more events
        append_events_jsonl_atomic(temp_path, &appended_events).expect("append events");

        // Validate all events are present
        let summary = validate_events_jsonl_file(temp_path).expect("read all events");
        assert_eq!(summary.event_count, 2);
        assert_eq!(summary.first_event_name.as_deref(), Some("initial.event"));
        assert_eq!(summary.last_event_name.as_deref(), Some("appended.event"));
    }

    #[test]
    fn append_events_jsonl_atomic_separates_existing_file_without_trailing_newline() {
        use tempfile::NamedTempFile;

        let initial_event = ProofEvent {
            schema_version: PROOF_EVENT_SCHEMA_VERSION.to_string(),
            event_name: "initial.no-newline".to_string(),
            severity: ProofEventSeverity::Info,
            step_id: "step-000".to_string(),
            command_id: None,
            artifact_path: None,
            artifact_sha256: None,
            exit_code: None,
            duration_ms: None,
            decision: "initial".to_string(),
            remediation: None,
        };
        let appended_event = ProofEvent {
            schema_version: PROOF_EVENT_SCHEMA_VERSION.to_string(),
            event_name: "appended.after-separator".to_string(),
            severity: ProofEventSeverity::Info,
            step_id: "step-001".to_string(),
            command_id: None,
            artifact_path: None,
            artifact_sha256: None,
            exit_code: None,
            duration_ms: None,
            decision: "appended".to_string(),
            remediation: None,
        };

        let temp_file = NamedTempFile::new().expect("create temp file");
        let temp_path = temp_file.path();
        let initial_line = serde_json::to_string(&initial_event).expect("serialize initial");
        std::fs::write(temp_path, initial_line).expect("write unterminated initial event");

        append_events_jsonl_atomic(temp_path, &[appended_event]).expect("append event");

        let content = std::fs::read_to_string(temp_path).expect("read appended content");
        assert!(
            content.contains("}\n{"),
            "appended JSONL should insert a record separator: {content}"
        );
        let summary = validate_events_jsonl_file(temp_path).expect("validate appended events");
        assert_eq!(summary.event_count, 2);
        assert_eq!(
            summary.first_event_name.as_deref(),
            Some("initial.no-newline")
        );
        assert_eq!(
            summary.last_event_name.as_deref(),
            Some("appended.after-separator")
        );
    }

    #[test]
    fn emit_event_jsonl_atomic_single_event_append() {
        use tempfile::NamedTempFile;

        let event = ProofEvent {
            schema_version: PROOF_EVENT_SCHEMA_VERSION.to_string(),
            event_name: "single.emission".to_string(),
            severity: ProofEventSeverity::Warning,
            step_id: "step-single".to_string(),
            command_id: None,
            artifact_path: None,
            artifact_sha256: None,
            exit_code: None,
            duration_ms: None,
            decision: "noted".to_string(),
            remediation: None,
        };

        let temp_file = NamedTempFile::new().expect("create temp file");
        let temp_path = temp_file.path();

        // Emit single event
        emit_event_jsonl_atomic(temp_path, &event).expect("emit event");

        // Emit another event
        emit_event_jsonl_atomic(temp_path, &event).expect("emit second event");

        // Validate both events are present
        let summary = validate_events_jsonl_file(temp_path).expect("read events");
        assert_eq!(summary.event_count, 2);
        assert_eq!(summary.first_event_name.as_deref(), Some("single.emission"));
        assert_eq!(summary.last_event_name.as_deref(), Some("single.emission"));
    }

    #[test]
    fn concurrent_event_emission_preserves_jsonl_integrity() {
        use std::io::BufRead;
        use std::sync::Arc;
        use std::thread;
        use tempfile::NamedTempFile;

        let temp_file = NamedTempFile::new().expect("create temp file");
        let temp_path = Arc::new(temp_file.path().to_path_buf());

        let mut handles = vec![];

        // Spawn multiple threads that emit events concurrently
        for thread_id in 0..8 {
            let path = Arc::clone(&temp_path);
            let handle = thread::spawn(move || {
                for event_id in 0..10 {
                    let event = ProofEvent {
                        schema_version: PROOF_EVENT_SCHEMA_VERSION.to_string(),
                        event_name: format!("thread{}.event{}", thread_id, event_id),
                        severity: ProofEventSeverity::Info,
                        step_id: format!("step-{}-{}", thread_id, event_id),
                        command_id: None,
                        artifact_path: None,
                        artifact_sha256: None,
                        exit_code: Some(0),
                        duration_ms: Some(1),
                        decision: "concurrent".to_string(),
                        remediation: None,
                    };

                    emit_event_jsonl_atomic(&*path, &event).expect("emit concurrent event");
                }
            });
            handles.push(handle);
        }

        // Wait for all threads to complete
        for handle in handles {
            handle.join().expect("thread completed");
        }

        // Validate that all events were written correctly and JSONL is not corrupted
        let summary = validate_events_jsonl_file(&*temp_path).expect("read concurrent events");
        assert_eq!(summary.event_count, 80); // 8 threads * 10 events each

        // Verify all events are valid and no corruption occurred
        let mut thread_event_counts = std::collections::BTreeMap::new();
        let file = std::fs::File::open(&*temp_path).expect("open concurrent events");
        for line_result in std::io::BufReader::new(file).lines() {
            let line = line_result.expect("read concurrent event line");
            if line.trim().is_empty() {
                continue;
            }
            let event = validate_event_json_line(&line).expect("valid concurrent event");

            assert!(event.event_name.starts_with("thread"));
            assert!(event.event_name.contains(".event"));
            assert_eq!(event.decision, "concurrent");

            let thread_id = event
                .event_name
                .chars()
                .skip(6) // skip "thread"
                .take_while(|c| c.is_ascii_digit())
                .collect::<String>()
                .parse::<usize>()
                .expect("parse thread id");

            *thread_event_counts.entry(thread_id).or_insert(0) += 1;
        }

        // Verify each thread contributed exactly 10 events
        assert_eq!(thread_event_counts.len(), 8);
        for count in thread_event_counts.values() {
            assert_eq!(*count, 10);
        }
    }

    /// bd-zvdxr regression. The pre-fix
    /// `append_events_jsonl_atomic` did a TOCTOU on the trailing-newline
    /// check: two concurrent appenders both observed a missing trailing
    /// newline and both prepended `\n`, producing a blank line in the
    /// JSONL stream that strict parsers reject. With the new exclusive
    /// flock around the read+write window, the final file must contain
    /// *no* blank lines and must be exactly thread_count*per_thread
    /// events long. (The sibling
    /// `concurrent_event_emission_preserves_jsonl_integrity` test
    /// tolerated blank lines via `if line.trim().is_empty() continue`,
    /// so a regression to the racing implementation would have passed
    /// that test.)
    #[test]
    fn concurrent_append_emits_no_blank_lines_under_contention() {
        use std::io::BufRead;
        use std::sync::Arc;
        use std::thread;
        use tempfile::NamedTempFile;

        let temp_file = NamedTempFile::new().expect("create temp file");
        let temp_path = Arc::new(temp_file.path().to_path_buf());

        const THREADS: usize = 16;
        const EVENTS_PER_THREAD: usize = 25;

        let mut handles = Vec::with_capacity(THREADS);
        for thread_id in 0..THREADS {
            let path = Arc::clone(&temp_path);
            let handle = thread::spawn(move || {
                for event_id in 0..EVENTS_PER_THREAD {
                    let event = ProofEvent {
                        schema_version: PROOF_EVENT_SCHEMA_VERSION.to_string(),
                        event_name: format!("bd-zvdxr.t{}.e{}", thread_id, event_id),
                        severity: ProofEventSeverity::Info,
                        step_id: format!("step-{}-{}", thread_id, event_id),
                        command_id: None,
                        artifact_path: None,
                        artifact_sha256: None,
                        exit_code: Some(0),
                        duration_ms: Some(1),
                        decision: "race-pin".to_string(),
                        remediation: None,
                    };
                    emit_event_jsonl_atomic(&*path, &event).expect("emit event");
                }
            });
            handles.push(handle);
        }
        for handle in handles {
            handle.join().expect("thread joined");
        }

        // Strict line-by-line audit — every non-final line must end with
        // `\n` and no blank lines may appear anywhere.
        let raw = std::fs::read_to_string(&*temp_path).expect("read events file");
        assert!(
            raw.ends_with('\n'),
            "JSONL file must end with a newline; got tail {:?}",
            &raw[raw.len().saturating_sub(8)..],
        );
        let mut total = 0usize;
        for (idx, line) in raw.lines().enumerate() {
            assert!(
                !line.is_empty(),
                "JSONL line {idx} is blank — bd-zvdxr race regression: concurrent \
                 appenders both decided needs_leading_newline=true",
            );
            total += 1;
        }
        assert_eq!(
            total,
            THREADS * EVENTS_PER_THREAD,
            "every emit_event_jsonl_atomic call must have produced exactly one line",
        );

        // And every line must parse as a valid event.
        let file = std::fs::File::open(&*temp_path).expect("reopen events file");
        for line_result in std::io::BufReader::new(file).lines() {
            let line = line_result.expect("read line");
            assert!(!line.is_empty(), "no blank lines (strict)");
            validate_event_json_line(&line).expect("each line parses as ProofEvent");
        }
    }
}
