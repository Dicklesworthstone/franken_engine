use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::fmt;
use std::fs;
use std::path::{Component, Path};

pub const PROOF_MANIFEST_SCHEMA_VERSION: &str = "franken-engine.proof-artifact-manifest.v1";
pub const PROOF_EVENT_SCHEMA_VERSION: &str = "franken-engine.proof-artifact-event.v1";
pub const PROOF_REPORT_SCHEMA_VERSION: &str = "franken-engine.proof-artifact-report.v1";
pub const REDACTION_POLICY_SCHEMA_VERSION: &str =
    "franken-engine.proof-artifact-redaction-policy.v1";

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
}

impl fmt::Display for ProofArtifactError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnknownSchema { expected, actual } => {
                write!(f, "unknown schema version: expected {expected}, got {actual}")
            }
            Self::MissingField(field) => write!(f, "missing required field: {field}"),
            Self::InvalidPath(path) => write!(f, "invalid artifact path: {path}"),
            Self::InvalidState(state) => write!(f, "invalid proof state: {state}"),
            Self::Io(error) => write!(f, "proof artifact I/O error: {error}"),
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
                "TOKEN".to_string(),
                "SECRET".to_string(),
                "PASSWORD".to_string(),
                "CREDENTIAL".to_string(),
                "AUTH".to_string(),
                "KEY".to_string(),
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

    input
        .split_whitespace()
        .map(|token| redact_token(token, &fragments, &policy.replacement))
        .collect::<Vec<_>>()
        .join(" ")
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
    let bytes = fs::read(path).map_err(|error| ProofArtifactError::Io(error.to_string()))?;
    Ok(sha256_hex(bytes))
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

fn redact_token(token: &str, fragments: &[String], replacement: &str) -> String {
    if let Some((key, _value)) = token.split_once('=') {
        let key_upper = key.to_ascii_uppercase();
        if fragments
            .iter()
            .any(|fragment| key_upper.contains(fragment))
        {
            return format!("{key}={replacement}");
        }
    }

    if let Some(rest) = token.strip_prefix("Bearer") {
        if !rest.is_empty() {
            return format!("Bearer{replacement}");
        }
    }

    token.to_string()
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
}
