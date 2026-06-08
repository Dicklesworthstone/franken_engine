//! Lean proof producer for strict proof.json artifacts.
//!
//! This module is the engine-side producer contract for `proofs/lean4/`.
//! It runs a configured `lake build`, hashes the Lean proof inputs and build
//! outputs, and emits a [`ProofProducerArtifact`] that the proof schema
//! validates fail-closed.

use std::collections::BTreeMap;
use std::fmt;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::Duration;

use serde::{Deserialize, Serialize};
use wait_timeout::ChildExt;

use crate::hash_tiers::ContentHash;
use crate::proof_schema::{
    ProofCheckerResult, ProofProducerArtifact, ProofSignatureOrContentHash, ProofToolIdentity,
    proof_schema_version_current, validate_proof_producer_artifact,
};
use crate::security_epoch::SecurityEpoch;

/// Default claim backed by the checked-in Lean proof corpus.
pub const LEAN_PROOF_CLAIM_ID: &str = "FE-CLAIM-016";

/// Stable validator ID used inside strict proof producer artifacts.
pub const LEAN_THEOREM_VALIDATOR_ID: &str = "lean4::proofs/lean4";

/// A command line used by the Lean producer.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CommandSpec {
    /// Program to execute.
    pub program: String,
    /// Arguments passed to the program.
    pub args: Vec<String>,
}

impl CommandSpec {
    /// Create a command spec.
    pub fn new(program: impl Into<String>) -> Self {
        Self {
            program: program.into(),
            args: Vec::new(),
        }
    }

    /// Append one argument.
    pub fn arg(mut self, arg: impl Into<String>) -> Self {
        self.args.push(arg.into());
        self
    }

    /// Append many arguments.
    pub fn args(mut self, args: impl IntoIterator<Item = impl Into<String>>) -> Self {
        self.args.extend(args.into_iter().map(Into::into));
        self
    }

    fn display_command(&self) -> String {
        std::iter::once(quote_shell_token(&self.program))
            .chain(self.args.iter().map(|arg| quote_shell_token(arg)))
            .collect::<Vec<_>>()
            .join(" ")
    }
}

/// Configuration for a Lean proof producer run.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LeanProofProducerConfig {
    /// Directory containing `lakefile.lean`, `lean-toolchain`, and proof files.
    pub proof_dir: PathBuf,
    /// Claim IDs backed by this proof corpus.
    pub claim_ids: Vec<String>,
    /// Tool invocation ID for audit correlation.
    pub tool_invocation_id: String,
    /// Replay tick for this producer run.
    pub timestamp_ticks: u64,
    /// Security/logical epoch for this producer run.
    pub logical_epoch: SecurityEpoch,
    /// `lake build` command.
    pub lake_build: CommandSpec,
    /// Lean version command.
    pub lean_version: CommandSpec,
    /// Lake version command.
    pub lake_version: CommandSpec,
    /// Optional timeout applied independently to each external command.
    pub command_timeout: Option<Duration>,
}

impl LeanProofProducerConfig {
    /// Create the default configuration for a Lean proof directory.
    pub fn new(proof_dir: impl Into<PathBuf>) -> Self {
        Self {
            proof_dir: proof_dir.into(),
            claim_ids: vec![LEAN_PROOF_CLAIM_ID.to_string()],
            tool_invocation_id: "lean-proof-producer".to_string(),
            timestamp_ticks: 0,
            logical_epoch: SecurityEpoch::GENESIS,
            lake_build: CommandSpec::new("lake").arg("build"),
            lean_version: CommandSpec::new("lean").arg("--version"),
            lake_version: CommandSpec::new("lake").arg("--version"),
            command_timeout: Some(Duration::from_secs(300)),
        }
    }
}

/// Result of a successful producer run.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LeanProofProducerReport {
    /// Strict proof producer artifact.
    pub artifact: ProofProducerArtifact,
    /// Theorem declarations found in the successfully-built Lean corpus.
    pub theorem_ids: Vec<String>,
}

/// Errors from the Lean proof producer.
#[derive(Debug)]
pub enum LeanProofProducerError {
    /// Required proof directory entry is missing.
    MissingProofInput { path: PathBuf },
    /// Proof input could not be read.
    Io {
        path: PathBuf,
        source: std::io::Error,
    },
    /// External command failed to spawn or collect.
    CommandIo {
        command: String,
        source: std::io::Error,
    },
    /// External command timed out.
    CommandTimedOut { command: String, timeout: Duration },
    /// External command exited unsuccessfully.
    CommandFailed {
        command: String,
        status: Option<i32>,
        stderr: String,
    },
    /// Lean build succeeded but no theorem declarations were found.
    MissingTheorems { proof_dir: PathBuf },
    /// Strict artifact validation failed.
    InvalidArtifact(crate::proof_schema::ProofSchemaError),
    /// Artifact serialization failed.
    Serialize(serde_json::Error),
}

impl fmt::Display for LeanProofProducerError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::MissingProofInput { path } => {
                write!(f, "missing Lean proof input: {}", path.display())
            }
            Self::Io { path, source } => {
                write!(f, "I/O error for {}: {source}", path.display())
            }
            Self::CommandIo { command, source } => {
                write!(f, "command I/O error for `{command}`: {source}")
            }
            Self::CommandTimedOut { command, timeout } => {
                write!(f, "command `{command}` timed out after {timeout:?}")
            }
            Self::CommandFailed {
                command,
                status,
                stderr,
            } => write!(
                f,
                "command `{command}` failed with status {:?}: {}",
                status,
                stderr.trim()
            ),
            Self::MissingTheorems { proof_dir } => write!(
                f,
                "Lean build succeeded but no theorem declarations were found under {}",
                proof_dir.display()
            ),
            Self::InvalidArtifact(source) => write!(f, "invalid Lean proof artifact: {source}"),
            Self::Serialize(source) => write!(f, "serialize Lean proof artifact: {source}"),
        }
    }
}

impl std::error::Error for LeanProofProducerError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Io { source, .. } | Self::CommandIo { source, .. } => Some(source),
            Self::InvalidArtifact(source) => Some(source),
            Self::Serialize(source) => Some(source),
            Self::MissingProofInput { .. }
            | Self::CommandTimedOut { .. }
            | Self::CommandFailed { .. }
            | Self::MissingTheorems { .. } => None,
        }
    }
}

impl From<crate::proof_schema::ProofSchemaError> for LeanProofProducerError {
    fn from(value: crate::proof_schema::ProofSchemaError) -> Self {
        Self::InvalidArtifact(value)
    }
}

impl From<serde_json::Error> for LeanProofProducerError {
    fn from(value: serde_json::Error) -> Self {
        Self::Serialize(value)
    }
}

/// Run the configured Lean proof producer and return a strict proof artifact.
pub fn produce_lean_proof_artifact(
    config: &LeanProofProducerConfig,
) -> Result<LeanProofProducerReport, LeanProofProducerError> {
    validate_lean_proof_dir(&config.proof_dir)?;
    let input_hashes = collect_input_artifact_hashes(&config.proof_dir)?;

    let lean_version = run_command(
        &config.lean_version,
        &config.proof_dir,
        config.command_timeout,
    );
    let lake_version = run_command(
        &config.lake_version,
        &config.proof_dir,
        config.command_timeout,
    );
    let mut output_hashes = BTreeMap::new();
    record_command_result("lean-version", &lean_version, &mut output_hashes);
    record_command_result("lake-version", &lake_version, &mut output_hashes);

    let tool_version = format!(
        "lean:{};lake:{}",
        command_version_line(&lean_version),
        command_version_line(&lake_version)
    );
    output_hashes.insert(
        "tool_versions".to_string(),
        ContentHash::compute(tool_version.as_bytes()),
    );

    if let Some(reason) = unavailable_reason("lean version", &config.lean_version, &lean_version) {
        let artifact = proof_artifact(
            config,
            input_hashes,
            output_hashes,
            tool_version,
            ProofCheckerResult::Unavailable { reason },
        );
        return Ok(LeanProofProducerReport {
            artifact,
            theorem_ids: Vec::new(),
        });
    }
    if let Some(reason) = unavailable_reason("lake version", &config.lake_version, &lake_version) {
        let artifact = proof_artifact(
            config,
            input_hashes,
            output_hashes,
            tool_version,
            ProofCheckerResult::Unavailable { reason },
        );
        return Ok(LeanProofProducerReport {
            artifact,
            theorem_ids: Vec::new(),
        });
    }

    let build = run_command(
        &config.lake_build,
        &config.proof_dir,
        config.command_timeout,
    );
    record_command_result("lake-build", &build, &mut output_hashes);
    let build = match build {
        Ok(build) if build.status_success => build,
        result => {
            let reason = unavailable_reason("lake build", &config.lake_build, &result)
                .unwrap_or_else(|| "lake build unavailable".to_string());
            let artifact = proof_artifact(
                config,
                input_hashes,
                output_hashes,
                tool_version,
                ProofCheckerResult::Unavailable { reason },
            );
            return Ok(LeanProofProducerReport {
                artifact,
                theorem_ids: Vec::new(),
            });
        }
    };

    output_hashes.insert(
        "lake-build.stdout".to_string(),
        ContentHash::compute(build.stdout.as_bytes()),
    );
    output_hashes.insert(
        "lake-build.stderr".to_string(),
        ContentHash::compute(build.stderr.as_bytes()),
    );

    let theorem_ids = collect_theorem_ids(&config.proof_dir)?;
    if theorem_ids.is_empty() {
        let artifact = proof_artifact(
            config,
            input_hashes,
            output_hashes,
            tool_version,
            ProofCheckerResult::Unavailable {
                reason: "lake build succeeded but no theorem declarations were found".to_string(),
            },
        );
        return Ok(LeanProofProducerReport {
            artifact,
            theorem_ids,
        });
    }

    output_hashes.insert(
        "theorem_ids".to_string(),
        ContentHash::compute(theorem_ids.join("\n").as_bytes()),
    );

    let artifact = proof_artifact(
        config,
        input_hashes,
        output_hashes,
        tool_version,
        ProofCheckerResult::Passed,
    );
    validate_proof_producer_artifact(&artifact)?;

    Ok(LeanProofProducerReport {
        artifact,
        theorem_ids,
    })
}

fn proof_artifact(
    config: &LeanProofProducerConfig,
    input_artifact_hashes: BTreeMap<String, ContentHash>,
    output_artifact_hashes: BTreeMap<String, ContentHash>,
    tool_version: String,
    checker_result: ProofCheckerResult,
) -> ProofProducerArtifact {
    let mut artifact = ProofProducerArtifact {
        schema_version: proof_schema_version_current(),
        claim_ids: config.claim_ids.clone(),
        theorem_or_validator_id: LEAN_THEOREM_VALIDATOR_ID.to_string(),
        input_artifact_hashes,
        output_artifact_hashes,
        command: format!(
            "cd {} && {}",
            quote_shell_token(&config.proof_dir.display().to_string()),
            config.lake_build.display_command()
        ),
        tool_identity: ProofToolIdentity {
            tool_name: "lean4".to_string(),
            tool_version,
            tool_invocation_id: config.tool_invocation_id.clone(),
        },
        checker_result,
        counterexample_artifacts: BTreeMap::new(),
        timestamp_ticks: config.timestamp_ticks,
        logical_epoch: config.logical_epoch,
        signature_or_content_hash: ProofSignatureOrContentHash::ContentHash(ContentHash::default()),
    };
    artifact.signature_or_content_hash =
        ProofSignatureOrContentHash::ContentHash(artifact.content_hash());
    artifact
}

/// Produce and write a strict Lean `proof.json` artifact.
pub fn write_lean_proof_artifact(
    config: &LeanProofProducerConfig,
    output_path: impl AsRef<Path>,
) -> Result<LeanProofProducerReport, LeanProofProducerError> {
    let report = produce_lean_proof_artifact(config)?;
    let output_path = output_path.as_ref();
    if let Some(parent) = output_path.parent() {
        fs::create_dir_all(parent).map_err(|source| LeanProofProducerError::Io {
            path: parent.to_path_buf(),
            source,
        })?;
    }
    let json = serde_json::to_string_pretty(&report.artifact)?;
    fs::write(output_path, format!("{json}\n")).map_err(|source| LeanProofProducerError::Io {
        path: output_path.to_path_buf(),
        source,
    })?;
    Ok(report)
}

fn validate_lean_proof_dir(proof_dir: &Path) -> Result<(), LeanProofProducerError> {
    for required in ["lakefile.lean", "lean-toolchain"] {
        let path = proof_dir.join(required);
        if !path.is_file() {
            return Err(LeanProofProducerError::MissingProofInput { path });
        }
    }
    if collect_lean_files(proof_dir)?.is_empty() {
        return Err(LeanProofProducerError::MissingProofInput {
            path: proof_dir.join("*.lean"),
        });
    }
    Ok(())
}

fn collect_input_artifact_hashes(
    proof_dir: &Path,
) -> Result<BTreeMap<String, ContentHash>, LeanProofProducerError> {
    let mut paths = vec![
        proof_dir.join("lakefile.lean"),
        proof_dir.join("lean-toolchain"),
    ];
    paths.extend(collect_lean_files(proof_dir)?);
    paths.sort();
    paths.dedup();

    let mut hashes = BTreeMap::new();
    for path in paths {
        let bytes = fs::read(&path).map_err(|source| LeanProofProducerError::Io {
            path: path.clone(),
            source,
        })?;
        hashes.insert(
            relative_proof_path(proof_dir, &path),
            ContentHash::compute(&bytes),
        );
    }
    Ok(hashes)
}

fn collect_lean_files(proof_dir: &Path) -> Result<Vec<PathBuf>, LeanProofProducerError> {
    let mut files = Vec::new();
    collect_lean_files_inner(proof_dir, &mut files)?;
    files.sort();
    Ok(files)
}

fn collect_lean_files_inner(
    dir: &Path,
    files: &mut Vec<PathBuf>,
) -> Result<(), LeanProofProducerError> {
    for entry in fs::read_dir(dir).map_err(|source| LeanProofProducerError::Io {
        path: dir.to_path_buf(),
        source,
    })? {
        let entry = entry.map_err(|source| LeanProofProducerError::Io {
            path: dir.to_path_buf(),
            source,
        })?;
        let path = entry.path();
        let file_type = entry
            .file_type()
            .map_err(|source| LeanProofProducerError::Io {
                path: path.clone(),
                source,
            })?;
        if file_type.is_dir() {
            collect_lean_files_inner(&path, files)?;
        } else if path.extension().is_some_and(|ext| ext == "lean") {
            files.push(path);
        }
    }
    Ok(())
}

fn collect_theorem_ids(proof_dir: &Path) -> Result<Vec<String>, LeanProofProducerError> {
    let mut theorem_ids = Vec::new();
    for path in collect_lean_files(proof_dir)? {
        let source = fs::read_to_string(&path).map_err(|source| LeanProofProducerError::Io {
            path: path.clone(),
            source,
        })?;
        for line in source.lines() {
            if let Some(theorem_id) = parse_theorem_id(line) {
                theorem_ids.push(theorem_id.to_string());
            }
        }
    }
    theorem_ids.sort();
    theorem_ids.dedup();
    Ok(theorem_ids)
}

fn parse_theorem_id(line: &str) -> Option<&str> {
    let rest = line.trim_start().strip_prefix("theorem ")?;
    let theorem_id = rest
        .split(|ch: char| !(ch.is_ascii_alphanumeric() || ch == '_' || ch == '.'))
        .next()
        .unwrap_or_default();
    (!theorem_id.is_empty()).then_some(theorem_id)
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct RawCommandOutput {
    status_success: bool,
    status_code: Option<i32>,
    stdout: String,
    stderr: String,
}

fn run_command(
    spec: &CommandSpec,
    current_dir: &Path,
    timeout: Option<Duration>,
) -> Result<RawCommandOutput, LeanProofProducerError> {
    let command = spec.display_command();
    let mut cmd = Command::new(&spec.program);
    cmd.args(&spec.args)
        .current_dir(current_dir)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());

    if let Some(timeout) = timeout {
        let mut child = cmd
            .spawn()
            .map_err(|source| LeanProofProducerError::CommandIo {
                command: command.clone(),
                source,
            })?;
        if child
            .wait_timeout(timeout)
            .map_err(|source| LeanProofProducerError::CommandIo {
                command: command.clone(),
                source,
            })?
            .is_none()
        {
            let _ = child.kill();
            let _ = child.wait();
            return Err(LeanProofProducerError::CommandTimedOut { command, timeout });
        }
        let output =
            child
                .wait_with_output()
                .map_err(|source| LeanProofProducerError::CommandIo {
                    command: command.clone(),
                    source,
                })?;
        return Ok(raw_output_from_process_output(output));
    }

    cmd.output()
        .map(raw_output_from_process_output)
        .map_err(|source| LeanProofProducerError::CommandIo { command, source })
}

fn record_command_result(
    label: &str,
    result: &Result<RawCommandOutput, LeanProofProducerError>,
    hashes: &mut BTreeMap<String, ContentHash>,
) {
    match result {
        Ok(output) => {
            hashes.insert(
                format!("{label}.stdout"),
                ContentHash::compute(output.stdout.as_bytes()),
            );
            hashes.insert(
                format!("{label}.stderr"),
                ContentHash::compute(output.stderr.as_bytes()),
            );
            hashes.insert(
                format!("{label}.status"),
                ContentHash::compute(format!("{:?}", output.status_code).as_bytes()),
            );
        }
        Err(error) => {
            hashes.insert(
                format!("{label}.error"),
                ContentHash::compute(error.to_string().as_bytes()),
            );
        }
    }
}

fn command_version_line(result: &Result<RawCommandOutput, LeanProofProducerError>) -> String {
    match result {
        Ok(output) if output.status_success => first_nonempty_line(&output.stdout),
        Ok(output) => format!("unavailable(status={:?})", output.status_code),
        Err(_) => "unavailable".to_string(),
    }
}

fn unavailable_reason(
    label: &str,
    spec: &CommandSpec,
    result: &Result<RawCommandOutput, LeanProofProducerError>,
) -> Option<String> {
    match result {
        Ok(output) if output.status_success => None,
        Ok(output) => Some(format!(
            "{label} command `{}` exited with status {:?}: {}",
            spec.display_command(),
            output.status_code,
            first_nonempty_line(&output.stderr)
        )),
        Err(error) => Some(format!(
            "{label} command `{}` unavailable: {error}",
            spec.display_command()
        )),
    }
}

fn raw_output_from_process_output(output: std::process::Output) -> RawCommandOutput {
    RawCommandOutput {
        status_success: output.status.success(),
        status_code: output.status.code(),
        stdout: String::from_utf8_lossy(&output.stdout).into_owned(),
        stderr: String::from_utf8_lossy(&output.stderr).into_owned(),
    }
}

fn relative_proof_path(proof_dir: &Path, path: &Path) -> String {
    path.strip_prefix(proof_dir)
        .unwrap_or(path)
        .components()
        .map(|component| component.as_os_str().to_string_lossy())
        .collect::<Vec<_>>()
        .join("/")
}

fn first_nonempty_line(value: &str) -> String {
    value
        .lines()
        .map(str::trim)
        .find(|line| !line.is_empty())
        .unwrap_or("unknown")
        .to_string()
}

fn quote_shell_token(token: &str) -> String {
    if token
        .chars()
        .all(|ch| ch.is_ascii_alphanumeric() || matches!(ch, '-' | '_' | '.' | '/' | ':'))
    {
        token.to_string()
    } else {
        format!("'{}'", token.replace('\'', "'\\''"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn write_fixture_proofs(dir: &Path, theorem_source: &str) {
        fs::write(dir.join("lakefile.lean"), "import Lake\nopen Lake DSL\n")
            .expect("write lakefile");
        fs::write(dir.join("lean-toolchain"), "leanprover/lean4:4.7.0\n")
            .expect("write lean-toolchain");
        fs::write(dir.join("IFCLatticeSpecification.lean"), theorem_source)
            .expect("write theorem file");
    }

    fn success_config(proof_dir: &Path) -> LeanProofProducerConfig {
        let mut config = LeanProofProducerConfig::new(proof_dir);
        config.tool_invocation_id = "test-run-001".to_string();
        config.timestamp_ticks = 42;
        config.logical_epoch = SecurityEpoch::from_raw(7);
        config.command_timeout = None;
        config.lean_version = CommandSpec::new("sh").args(["-c", "printf 'Lean 4.7.0\\n'"]);
        config.lake_version = CommandSpec::new("sh").args(["-c", "printf 'Lake 5.0.0\\n'"]);
        config.lake_build = CommandSpec::new("sh").args(["-c", "printf 'build ok\\n'"]);
        config
    }

    #[test]
    fn parse_theorem_id_extracts_top_level_names() {
        assert_eq!(
            parse_theorem_id("theorem join_idempotent (a : LabelClass) : true := by"),
            Some("join_idempotent")
        );
        assert_eq!(
            parse_theorem_id("  theorem Namespace.name : true := by"),
            Some("Namespace.name")
        );
        assert_eq!(parse_theorem_id("def helper := 1"), None);
    }

    #[test]
    fn produce_lean_proof_artifact_accepts_successful_build() {
        let temp = tempfile::tempdir().expect("tempdir");
        write_fixture_proofs(
            temp.path(),
            "theorem join_idempotent (a : Nat) : a = a := by rfl\n",
        );

        let report = produce_lean_proof_artifact(&success_config(temp.path())).expect("artifact");

        assert_eq!(report.artifact.claim_ids, vec![LEAN_PROOF_CLAIM_ID]);
        assert_eq!(report.theorem_ids, vec!["join_idempotent"]);
        assert_eq!(report.artifact.checker_result, ProofCheckerResult::Passed);
        assert!(
            report
                .artifact
                .input_artifact_hashes
                .contains_key("IFCLatticeSpecification.lean")
        );
        assert!(
            report
                .artifact
                .output_artifact_hashes
                .contains_key("lake-build.stdout")
        );
        assert!(validate_proof_producer_artifact(&report.artifact).is_ok());
    }

    #[test]
    fn produce_lean_proof_artifact_marks_failed_lake_build_unavailable() {
        let temp = tempfile::tempdir().expect("tempdir");
        write_fixture_proofs(temp.path(), "theorem ok : True := by trivial\n");
        let mut config = success_config(temp.path());
        config.lake_build = CommandSpec::new("sh").args(["-c", "printf 'boom\\n' >&2; exit 3"]);

        let report = produce_lean_proof_artifact(&config).expect("failed build yields artifact");

        assert_eq!(report.theorem_ids, Vec::<String>::new());
        assert!(matches!(
            report.artifact.checker_result,
            ProofCheckerResult::Unavailable {
                ref reason
            } if reason.contains("lake build")
        ));
        assert!(validate_proof_producer_artifact(&report.artifact).is_err());
    }

    #[test]
    fn produce_lean_proof_artifact_marks_missing_theorems_unavailable() {
        let temp = tempfile::tempdir().expect("tempdir");
        write_fixture_proofs(temp.path(), "def helper := 1\n");

        let report = produce_lean_proof_artifact(&success_config(temp.path()))
            .expect("missing theorem set yields artifact");

        assert_eq!(report.theorem_ids, Vec::<String>::new());
        assert!(matches!(
            report.artifact.checker_result,
            ProofCheckerResult::Unavailable {
                ref reason
            } if reason.contains("no theorem")
        ));
        assert!(validate_proof_producer_artifact(&report.artifact).is_err());
    }

    #[test]
    fn produce_lean_proof_artifact_rejects_missing_inputs() {
        let temp = tempfile::tempdir().expect("tempdir");

        let err = produce_lean_proof_artifact(&success_config(temp.path()))
            .expect_err("missing proof corpus rejected");

        assert!(matches!(
            err,
            LeanProofProducerError::MissingProofInput { .. }
        ));
    }

    #[test]
    fn proof_artifact_hash_changes_when_lean_input_changes() {
        let temp = tempfile::tempdir().expect("tempdir");
        write_fixture_proofs(temp.path(), "theorem first : True := by trivial\n");
        let first = produce_lean_proof_artifact(&success_config(temp.path()))
            .expect("first artifact")
            .artifact
            .content_hash();

        fs::write(
            temp.path().join("IFCLatticeSpecification.lean"),
            "theorem second : True := by trivial\n",
        )
        .expect("rewrite theorem file");
        let second = produce_lean_proof_artifact(&success_config(temp.path()))
            .expect("second artifact")
            .artifact
            .content_hash();

        assert_ne!(first, second);
    }

    #[test]
    fn write_lean_proof_artifact_round_trips_json() {
        let temp = tempfile::tempdir().expect("tempdir");
        write_fixture_proofs(temp.path(), "theorem ok : True := by trivial\n");
        let out = temp.path().join("proof.json");

        let report =
            write_lean_proof_artifact(&success_config(temp.path()), &out).expect("write artifact");
        let written: ProofProducerArtifact =
            serde_json::from_slice(&fs::read(&out).expect("read artifact")).expect("json");

        assert_eq!(written, report.artifact);
        assert!(validate_proof_producer_artifact(&written).is_ok());
    }
}
