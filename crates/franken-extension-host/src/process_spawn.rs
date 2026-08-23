//! Fail-closed process spawning for the extension host.
//!
//! This module deliberately contains no runtime or JavaScript types. The engine
//! presents a typed [`ProcessSpawnRequest`] only after its own capability, IFC,
//! and receipt checks. A host provider then independently verifies the narrow
//! [`ProcessSpawnCapability`] and an operator-supplied [`ProcessSpawnPolicy`]
//! before touching [`std::process`].
//!
//! The default [`DenyAllProcessSpawn`] provider performs no effects. The native
//! provider is suitable only when the product layer has installed an explicit
//! policy: it clears the ambient environment, confines working directories,
//! opens and verifies the canonical executable once, launches that same open
//! file identity instead of resolving the pathname twice, bounds
//! input/output/runtime, and exposes only provider-scoped opaque handles (never
//! native process identifiers).

#![forbid(unsafe_code)]

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::fs::File;
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::process::{Child, ChildStdin, Command, ExitStatus, Stdio};
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::sync::mpsc::{RecvTimeoutError, Sender, SyncSender, channel, sync_channel};
use std::sync::{Arc, Mutex, MutexGuard, Weak};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use std::os::fd::AsFd;
#[cfg(any(target_os = "linux", target_os = "freebsd"))]
use std::os::fd::AsRawFd;
#[cfg(unix)]
use std::os::unix::process::CommandExt;

/// Capability a caller must present for every process operation.
///
/// This type is intentionally independent of the engine and product runtimes.
/// They translate their authenticated grants into this narrow host-boundary
/// capability only after their own authorization checks.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProcessSpawnCapability {
    Spawn,
}

impl ProcessSpawnCapability {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Spawn => "process_spawn",
        }
    }
}

/// Process standard-I/O modes supported by the bounded native provider.
///
/// Ambient inherited streams are intentionally absent: output inherited by the
/// host cannot be captured, bounded, or replayed deterministically.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProcessStdioMode {
    Pipe,
    Null,
}

/// Standard-I/O configuration committed into a process request.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProcessStdio {
    pub stdin: ProcessStdioMode,
    pub stdout: ProcessStdioMode,
    pub stderr: ProcessStdioMode,
}

impl Default for ProcessStdio {
    fn default() -> Self {
        Self {
            stdin: ProcessStdioMode::Pipe,
            stdout: ProcessStdioMode::Pipe,
            stderr: ProcessStdioMode::Pipe,
        }
    }
}

/// A fully explicit launch description.
///
/// `env` augments the policy's fixed environment only after each key is
/// authorized. The native provider always calls `env_clear`; the host's ambient
/// environment can never leak into the child.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProcessLaunch {
    pub executable: String,
    #[serde(default)]
    pub argv: Vec<String>,
    #[serde(default)]
    pub env: BTreeMap<String, String>,
    #[serde(default)]
    pub cwd: Option<String>,
    /// Request policy-selected shell execution. Before preparation the caller
    /// must leave `executable` empty and put exactly one command string in
    /// `argv`; preparation replaces them with the signed shell path and exact
    /// `["-c", command]` argv before replay, recording, or live dispatch.
    #[serde(default)]
    pub shell: bool,
    #[serde(default)]
    pub stdio: ProcessStdio,
}

impl fmt::Debug for ProcessLaunch {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let argv_bytes = self.argv.iter().fold(0usize, |total, argument| {
            total.saturating_add(argument.len())
        });
        let env_key_bytes = self
            .env
            .keys()
            .fold(0usize, |total, key| total.saturating_add(key.len()));
        let env_value_bytes = self
            .env
            .values()
            .fold(0usize, |total, value| total.saturating_add(value.len()));

        f.debug_struct("ProcessLaunch")
            .field("executable_bytes", &self.executable.len())
            .field("argv_count", &self.argv.len())
            .field("argv_bytes", &argv_bytes)
            .field("env_count", &self.env.len())
            .field("env_key_bytes", &env_key_bytes)
            .field("env_value_bytes", &env_value_bytes)
            .field("cwd_present", &self.cwd.is_some())
            .field("cwd_bytes", &self.cwd.as_ref().map_or(0usize, String::len))
            .field("shell", &self.shell)
            .field("stdio", &self.stdio)
            .finish()
    }
}

/// Signal names accepted at the typed boundary.
///
/// The dependency-free native provider currently implements only `kill`,
/// because [`Child::kill`] is the only portable signal operation in `std`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProcessSignal {
    Interrupt,
    Terminate,
    Kill,
}

impl ProcessSignal {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Interrupt => "interrupt",
            Self::Terminate => "terminate",
            Self::Kill => "kill",
        }
    }
}

/// Typed process operation crossing the engine/host seam.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", tag = "operation", deny_unknown_fields)]
pub enum ProcessSpawnRequest {
    /// Launch, supply all input, close stdin, and wait for a bounded result.
    Run {
        launch: ProcessLaunch,
        #[serde(default)]
        stdin: Vec<u8>,
        #[serde(default)]
        timeout_millis: Option<u64>,
    },
    /// Launch a process and return a provider-scoped opaque handle.
    Spawn {
        launch: ProcessLaunch,
    },
    WriteStdin {
        handle: String,
        data: Vec<u8>,
    },
    CloseStdin {
        handle: String,
    },
    Wait {
        handle: String,
        #[serde(default)]
        timeout_millis: Option<u64>,
    },
    Kill {
        handle: String,
        signal: ProcessSignal,
    },
    /// Engine-owned compensating teardown. This operation is journaled but
    /// cannot be dispatched through the guest process-effect handler.
    Cleanup {
        handle: String,
    },
}

impl fmt::Debug for ProcessSpawnRequest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Run {
                launch,
                stdin,
                timeout_millis,
            } => f
                .debug_struct("ProcessSpawnRequest::Run")
                .field("launch", launch)
                .field("stdin_bytes", &stdin.len())
                .field("timeout_millis", timeout_millis)
                .finish(),
            Self::Spawn { launch } => f
                .debug_struct("ProcessSpawnRequest::Spawn")
                .field("launch", launch)
                .finish(),
            Self::WriteStdin { handle, data } => f
                .debug_struct("ProcessSpawnRequest::WriteStdin")
                .field("handle_bytes", &handle.len())
                .field("data_bytes", &data.len())
                .finish(),
            Self::CloseStdin { handle } => f
                .debug_struct("ProcessSpawnRequest::CloseStdin")
                .field("handle_bytes", &handle.len())
                .finish(),
            Self::Wait {
                handle,
                timeout_millis,
            } => f
                .debug_struct("ProcessSpawnRequest::Wait")
                .field("handle_bytes", &handle.len())
                .field("timeout_millis", timeout_millis)
                .finish(),
            Self::Kill { handle, signal } => f
                .debug_struct("ProcessSpawnRequest::Kill")
                .field("handle_bytes", &handle.len())
                .field("signal", signal)
                .finish(),
            Self::Cleanup { handle } => f
                .debug_struct("ProcessSpawnRequest::Cleanup")
                .field("handle_bytes", &handle.len())
                .finish(),
        }
    }
}

impl ProcessSpawnRequest {
    #[must_use]
    pub const fn kind(&self) -> &'static str {
        match self {
            Self::Run { .. } => "run",
            Self::Spawn { .. } => "spawn",
            Self::WriteStdin { .. } => "write_stdin",
            Self::CloseStdin { .. } => "close_stdin",
            Self::Wait { .. } => "wait",
            Self::Kill { .. } => "kill",
            Self::Cleanup { .. } => "cleanup",
        }
    }

    #[must_use]
    pub const fn required_capability(&self) -> ProcessSpawnCapability {
        ProcessSpawnCapability::Spawn
    }
}

const PROCESS_SPAWN_REQUEST_DIGEST_DOMAIN: &[u8] = b"franken-engine/process-spawn-request/v1\0";

/// Content digest used only to correlate bounded replay-divergence evidence.
///
/// The request remains the replay authority; this digest is not an
/// authorization token and never replaces the exact typed equality check.
pub(crate) fn process_spawn_request_digest(request: &ProcessSpawnRequest) -> [u8; 32] {
    let encoded = serde_json::to_vec(request)
        .expect("a typed process-spawn request must have an infallible JSON encoding");
    let mut digest = Sha256::new();
    digest.update(PROCESS_SPAWN_REQUEST_DIGEST_DOMAIN);
    digest.update(encoded);
    digest.finalize().into()
}

/// Platform-neutral exit information.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProcessExit {
    pub success: bool,
    pub code: Option<i32>,
    /// Unix terminating signal where the platform exposes it.
    pub signal: Option<i32>,
}

/// Successful process-provider response.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", tag = "kind", deny_unknown_fields)]
pub enum ProcessSpawnResponse {
    Run {
        exit: ProcessExit,
        stdout: Vec<u8>,
        stderr: Vec<u8>,
    },
    Spawned {
        handle: String,
    },
    StdinWritten {
        bytes_written: u64,
    },
    StdinClosed,
    Waited {
        exit: ProcessExit,
        stdout: Vec<u8>,
        stderr: Vec<u8>,
    },
    Killed {
        signal: ProcessSignal,
        exit: ProcessExit,
        stdout: Vec<u8>,
        stderr: Vec<u8>,
    },
    Cleaned {
        was_present: bool,
    },
}

impl fmt::Debug for ProcessSpawnResponse {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Run {
                exit,
                stdout,
                stderr,
            } => f
                .debug_struct("ProcessSpawnResponse::Run")
                .field("exit", exit)
                .field("stdout_bytes", &stdout.len())
                .field("stderr_bytes", &stderr.len())
                .finish(),
            Self::Spawned { handle } => f
                .debug_struct("ProcessSpawnResponse::Spawned")
                .field("handle_bytes", &handle.len())
                .finish(),
            Self::StdinWritten { bytes_written } => f
                .debug_struct("ProcessSpawnResponse::StdinWritten")
                .field("bytes_written", bytes_written)
                .finish(),
            Self::StdinClosed => f.write_str("ProcessSpawnResponse::StdinClosed"),
            Self::Waited {
                exit,
                stdout,
                stderr,
            } => f
                .debug_struct("ProcessSpawnResponse::Waited")
                .field("exit", exit)
                .field("stdout_bytes", &stdout.len())
                .field("stderr_bytes", &stderr.len())
                .finish(),
            Self::Killed {
                signal,
                exit,
                stdout,
                stderr,
            } => f
                .debug_struct("ProcessSpawnResponse::Killed")
                .field("signal", signal)
                .field("exit", exit)
                .field("stdout_bytes", &stdout.len())
                .field("stderr_bytes", &stderr.len())
                .finish(),
            Self::Cleaned { was_present } => f
                .debug_struct("ProcessSpawnResponse::Cleaned")
                .field("was_present", was_present)
                .finish(),
        }
    }
}

/// Stable fail-closed errors for process effects.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", tag = "kind", deny_unknown_fields)]
pub enum ProcessSpawnError {
    Denied {
        reason: String,
    },
    /// Dynamic IFC refused a non-public request before the provider ran.
    FlowPolicyBlocked,
    CapabilityMissing {
        capability: ProcessSpawnCapability,
    },
    PolicyViolation {
        code: String,
        detail: String,
    },
    LimitExceeded {
        limit: String,
        actual: u64,
        maximum: u64,
    },
    UnknownHandle {
        handle: String,
    },
    InvalidState {
        detail: String,
    },
    NotImplemented {
        what: String,
    },
    TimedOut {
        runtime_millis: u64,
    },
    Io {
        operation: String,
        detail: String,
    },
    ReplayDivergence {
        index: usize,
        live_kind: String,
        recorded_kind: String,
        /// Digest of the exact live request that failed replay matching.
        live_request_digest: [u8; 32],
        /// Digest of the expected request, or `None` when the transcript ended.
        recorded_request_digest: Option<[u8; 32]>,
    },
    /// A containment failure that also retains the bounded partial stream
    /// output captured before teardown completed (bd-k709s). The wrapped
    /// failure is the primary typed outcome; the captured prefixes are
    /// evidence for guest-visible Node-compatible error fields and are
    /// already capped by the policy per-stream output limit. Timeout and
    /// capture-capable I/O lanes always wrap, even when both captures are
    /// empty, so the outcome shape never depends on how much the child
    /// happened to print.
    PartialOutputFailed {
        failure: Box<ProcessSpawnError>,
        /// Terminating signal observed during the containment reap, when
        /// the platform exposes one.
        signal: Option<i32>,
        partial_stdout: Vec<u8>,
        partial_stderr: Vec<u8>,
    },
}

/// Stable `Io.operation` discriminator for an executable canonicalization
/// failure whose original [`std::io::ErrorKind`] was [`std::io::ErrorKind::NotFound`].
pub const PROCESS_SPAWN_CANONICALIZE_EXECUTABLE_NOT_FOUND_OPERATION: &str =
    "canonicalize executable:not_found";

/// Stable `Io.operation` discriminator for every new executable
/// canonicalization failure other than [`std::io::ErrorKind::NotFound`].
pub const PROCESS_SPAWN_CANONICALIZE_EXECUTABLE_OTHER_IO_OPERATION: &str =
    "canonicalize executable:other_io";

/// Pre-discriminator journals used this operation for every canonicalization
/// error and projected it to guest `ENOENT`. New in-tree producers never emit
/// it, but replay consumers retain the historical projection exactly.
pub const PROCESS_SPAWN_LEGACY_CANONICALIZE_EXECUTABLE_OPERATION: &str = "canonicalize executable";

/// Stable `Io.operation` discriminator when `Command::spawn` returns
/// [`std::io::ErrorKind::NotFound`] after validation, including executable,
/// script-interpreter, or working-directory races.
pub const PROCESS_SPAWN_EXECUTABLE_SPAWN_NOT_FOUND_OPERATION: &str = "spawn:not_found";

fn executable_canonicalize_error(error: std::io::Error) -> ProcessSpawnError {
    let operation = if error.kind() == std::io::ErrorKind::NotFound {
        PROCESS_SPAWN_CANONICALIZE_EXECUTABLE_NOT_FOUND_OPERATION
    } else {
        PROCESS_SPAWN_CANONICALIZE_EXECUTABLE_OTHER_IO_OPERATION
    };
    ProcessSpawnError::Io {
        operation: operation.to_string(),
        detail: error.to_string(),
    }
}

fn executable_spawn_error(error: std::io::Error) -> ProcessSpawnError {
    let operation = if error.kind() == std::io::ErrorKind::NotFound {
        PROCESS_SPAWN_EXECUTABLE_SPAWN_NOT_FOUND_OPERATION
    } else {
        "spawn"
    };
    ProcessSpawnError::Io {
        operation: operation.to_string(),
        detail: error.to_string(),
    }
}

impl fmt::Debug for ProcessSpawnError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Denied { reason } => f
                .debug_struct("ProcessSpawnError::Denied")
                .field("reason_bytes", &reason.len())
                .finish(),
            Self::FlowPolicyBlocked => f.write_str("ProcessSpawnError::FlowPolicyBlocked"),
            Self::CapabilityMissing { capability } => f
                .debug_struct("ProcessSpawnError::CapabilityMissing")
                .field("capability", capability)
                .finish(),
            Self::PolicyViolation { code, detail } => f
                .debug_struct("ProcessSpawnError::PolicyViolation")
                .field("code_bytes", &code.len())
                .field("detail_bytes", &detail.len())
                .finish(),
            Self::LimitExceeded {
                limit,
                actual,
                maximum,
            } => f
                .debug_struct("ProcessSpawnError::LimitExceeded")
                .field("limit_bytes", &limit.len())
                .field("actual", actual)
                .field("maximum", maximum)
                .finish(),
            Self::UnknownHandle { handle } => f
                .debug_struct("ProcessSpawnError::UnknownHandle")
                .field("handle_bytes", &handle.len())
                .finish(),
            Self::InvalidState { detail } => f
                .debug_struct("ProcessSpawnError::InvalidState")
                .field("detail_bytes", &detail.len())
                .finish(),
            Self::NotImplemented { what } => f
                .debug_struct("ProcessSpawnError::NotImplemented")
                .field("what_bytes", &what.len())
                .finish(),
            Self::TimedOut { runtime_millis } => f
                .debug_struct("ProcessSpawnError::TimedOut")
                .field("runtime_millis", runtime_millis)
                .finish(),
            Self::Io { operation, detail } => f
                .debug_struct("ProcessSpawnError::Io")
                .field("operation_bytes", &operation.len())
                .field("detail_bytes", &detail.len())
                .finish(),
            Self::ReplayDivergence {
                index,
                live_kind,
                recorded_kind,
                live_request_digest,
                recorded_request_digest,
            } => f
                .debug_struct("ProcessSpawnError::ReplayDivergence")
                .field("index", index)
                .field("live_kind_bytes", &live_kind.len())
                .field("recorded_kind_bytes", &recorded_kind.len())
                .field("live_request_digest", &hex_digest(live_request_digest))
                .field(
                    "recorded_request_digest",
                    &recorded_request_digest.as_ref().map(hex_digest),
                )
                .finish(),
            Self::PartialOutputFailed {
                failure,
                signal,
                partial_stdout,
                partial_stderr,
            } => f
                .debug_struct("ProcessSpawnError::PartialOutputFailed")
                .field("failure", failure)
                .field("signal", signal)
                .field("partial_stdout_len", &partial_stdout.len())
                .field("partial_stderr_len", &partial_stderr.len())
                .finish(),
        }
    }
}

impl fmt::Display for ProcessSpawnError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Denied { reason } => write!(
                f,
                "process spawn denied: redacted reason ({} bytes)",
                reason.len()
            ),
            Self::FlowPolicyBlocked => {
                write!(f, "process spawn denied: FLOW_POLICY_BLOCKED")
            }
            Self::CapabilityMissing { capability } => {
                write!(f, "process capability missing: {}", capability.as_str())
            }
            Self::PolicyViolation { code, detail } => write!(
                f,
                "process policy violation: redacted code ({} bytes), detail ({} bytes)",
                code.len(),
                detail.len()
            ),
            Self::LimitExceeded {
                limit,
                actual,
                maximum,
            } => write!(
                f,
                "process limit (redacted name, {} bytes) exceeded: {actual} > {maximum}",
                limit.len()
            ),
            Self::UnknownHandle { handle } => {
                write!(f, "unknown process handle ({} bytes)", handle.len())
            }
            Self::InvalidState { detail } => write!(
                f,
                "invalid process state: redacted detail ({} bytes)",
                detail.len()
            ),
            Self::NotImplemented { what } => write!(
                f,
                "process operation not implemented: redacted detail ({} bytes)",
                what.len()
            ),
            Self::TimedOut { runtime_millis } => {
                write!(f, "process timed out after {runtime_millis}ms")
            }
            Self::Io { operation, detail } => write!(
                f,
                "process I/O error: redacted operation ({} bytes), detail ({} bytes)",
                operation.len(),
                detail.len()
            ),
            Self::ReplayDivergence {
                index,
                live_kind,
                recorded_kind,
                live_request_digest,
                recorded_request_digest,
            } => write!(
                f,
                "process replay divergence at index {index}: redacted live kind ({} bytes) != recorded kind ({} bytes); live_request_sha256={}, recorded_request_sha256={}",
                live_kind.len(),
                recorded_kind.len(),
                hex_digest(live_request_digest),
                recorded_request_digest
                    .as_ref()
                    .map_or_else(|| "end_of_transcript".to_string(), hex_digest)
            ),
            Self::PartialOutputFailed {
                failure,
                signal,
                partial_stdout,
                partial_stderr,
            } => write!(
                f,
                "process failure with retained partial output: {failure}; signal {:?}; partial stdout ({} bytes), stderr ({} bytes)",
                signal,
                partial_stdout.len(),
                partial_stderr.len()
            ),
        }
    }
}

fn hex_digest(digest: &[u8; 32]) -> String {
    let mut encoded = String::with_capacity(64);
    for byte in digest {
        use std::fmt::Write as _;
        write!(&mut encoded, "{byte:02x}").expect("writing to String cannot fail");
    }
    encoded
}

impl std::error::Error for ProcessSpawnError {}

pub type ProcessSpawnOutcome = Result<ProcessSpawnResponse, ProcessSpawnError>;

/// Live execution control checked by effectful process providers.
///
/// The engine supplies a control that combines the cell cancellation signal
/// with the exact process-attempt authority. Native providers poll it while
/// hashing, launching, waiting, and draining. Cleanup deliberately does not
/// take a control: containment must remain available after cancellation,
/// expiry, or revocation.
pub trait ProcessSpawnControl: fmt::Debug + Send + Sync {
    /// Refuse further native work when the enclosing execution is no longer
    /// authorized to continue.
    fn checkpoint(&self) -> Result<(), ProcessSpawnError>;
}

/// Control used by direct provider callers that have no enclosing cell.
#[derive(Debug, Clone, Copy, Default)]
pub struct UnrestrictedProcessSpawnControl;

impl ProcessSpawnControl for UnrestrictedProcessSpawnControl {
    fn checkpoint(&self) -> Result<(), ProcessSpawnError> {
        Ok(())
    }
}

/// Resource ceilings applied to every native provider instance.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProcessSpawnLimits {
    pub max_children: u64,
    /// Maximum bytes in the requested executable path.
    pub max_executable_path_bytes: u64,
    /// Maximum executable image size inspected by SHA-256 verification.
    pub max_executable_bytes: u64,
    pub max_argv_count: u64,
    pub max_argv_bytes: u64,
    pub max_env_count: u64,
    /// Aggregate key + value bytes after fixed and request env are merged.
    pub max_env_bytes: u64,
    pub max_cwd_bytes: u64,
    /// Aggregate executable path + argv + env + cwd bytes admitted before any
    /// canonicalization, hashing, or process creation.
    pub max_prelaunch_bytes: u64,
    /// Maximum canonical JSON bytes for every request kind. The exact encoded
    /// size is counted through a non-allocating writer before callers clone or
    /// hash the request.
    pub max_request_bytes: u64,
    pub max_stdin_bytes: u64,
    /// Per-stream capture cap.
    pub max_output_bytes: u64,
    pub max_runtime_millis: u64,
}

impl Default for ProcessSpawnLimits {
    fn default() -> Self {
        Self {
            max_children: 4,
            max_executable_path_bytes: 4 * 1024,
            max_executable_bytes: 128 * 1024 * 1024,
            max_argv_count: 128,
            max_argv_bytes: 64 * 1024,
            max_env_count: 128,
            max_env_bytes: 64 * 1024,
            max_cwd_bytes: 4 * 1024,
            max_prelaunch_bytes: 128 * 1024,
            max_request_bytes: 16 * 1024 * 1024,
            max_stdin_bytes: 1024 * 1024,
            max_output_bytes: 4 * 1024 * 1024,
            max_runtime_millis: 30_000,
        }
    }
}

/// Operator policy for the native process provider.
///
/// `allowed_executables` maps an exact canonical path string to the SHA-256
/// digest of the file authorized at that path. Both path and digest must match
/// the opened executable file identity used for launch. An empty map denies
/// every executable.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProcessSpawnPolicy {
    pub allowed_executables: BTreeMap<String, [u8; 32]>,
    /// Signed deterministic resolution for bare executable names.
    ///
    /// Values must also be exact keys in `allowed_executables`. The ambient
    /// `PATH` is never consulted.
    #[serde(default)]
    pub executable_aliases: BTreeMap<String, String>,
    #[serde(default)]
    pub allow_shell: bool,
    /// Alias in `executable_aliases` selected as the one authorized shell.
    #[serde(default)]
    pub shell_executable_alias: Option<String>,
    #[serde(default)]
    pub allowed_env_keys: BTreeSet<String>,
    #[serde(default)]
    pub fixed_env: BTreeMap<String, String>,
    /// Canonical directory that contains every permitted working directory.
    pub jailed_cwd_root: String,
    pub limits: ProcessSpawnLimits,
    #[serde(default)]
    pub allowed_signals: BTreeSet<ProcessSignal>,
    #[serde(default)]
    pub allowed_stdio: BTreeSet<ProcessStdioMode>,
}

impl fmt::Debug for ProcessSpawnPolicy {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ProcessSpawnPolicy")
            .field("allowed_executable_count", &self.allowed_executables.len())
            .field("executable_alias_count", &self.executable_aliases.len())
            .field("allow_shell", &self.allow_shell)
            .field(
                "shell_executable_alias_present",
                &self.shell_executable_alias.is_some(),
            )
            .field("allowed_env_key_count", &self.allowed_env_keys.len())
            .field("fixed_env_count", &self.fixed_env.len())
            .field("jailed_cwd_root_bytes", &self.jailed_cwd_root.len())
            .field("limits", &self.limits)
            .field("allowed_signals", &self.allowed_signals)
            .field("allowed_stdio", &self.allowed_stdio)
            .finish()
    }
}

impl Default for ProcessSpawnPolicy {
    fn default() -> Self {
        Self {
            allowed_executables: BTreeMap::new(),
            executable_aliases: BTreeMap::new(),
            allow_shell: false,
            shell_executable_alias: None,
            allowed_env_keys: BTreeSet::new(),
            fixed_env: BTreeMap::new(),
            jailed_cwd_root: String::new(),
            limits: ProcessSpawnLimits::default(),
            allowed_signals: BTreeSet::from([ProcessSignal::Kill, ProcessSignal::Terminate]),
            allowed_stdio: BTreeSet::from([ProcessStdioMode::Pipe, ProcessStdioMode::Null]),
        }
    }
}

impl ProcessSpawnPolicy {
    /// Construct a deny-by-default policy rooted at an existing directory.
    pub fn jailed(root: impl AsRef<Path>) -> Result<Self, ProcessSpawnError> {
        let root = canonical_directory(root.as_ref(), "canonicalize jailed cwd root")?;
        Ok(Self {
            jailed_cwd_root: path_string(&root)?,
            ..Self::default()
        })
    }

    /// Add one exact canonical executable and its current SHA-256 digest.
    ///
    /// The provider opens and re-hashes the file before every launch; this
    /// method does not turn the setup-time digest into a trust-on-first-use
    /// bypass.
    pub fn authorize_executable(
        &mut self,
        executable: impl AsRef<Path>,
    ) -> Result<String, ProcessSpawnError> {
        let canonical =
            std::fs::canonicalize(executable.as_ref()).map_err(executable_canonicalize_error)?;
        if !canonical.is_file() {
            return Err(ProcessSpawnError::PolicyViolation {
                code: "executable_not_file".to_string(),
                detail: canonical.display().to_string(),
            });
        }
        let canonical = path_string(&canonical)?;
        enforce_limit(
            "executable_path_bytes",
            u64::try_from(canonical.len()).unwrap_or(u64::MAX),
            self.limits.max_executable_path_bytes,
        )?;
        let digest = digest_file(Path::new(&canonical), self.limits.max_executable_bytes)?;
        self.allowed_executables.insert(canonical.clone(), digest);
        Ok(canonical)
    }

    /// Authorize a bare executable alias and bind it to one exact executable.
    pub fn authorize_alias(
        &mut self,
        alias: impl Into<String>,
        executable: impl AsRef<Path>,
    ) -> Result<String, ProcessSpawnError> {
        let alias = alias.into();
        validate_executable_alias(&alias)?;
        let canonical = self.authorize_executable(executable)?;
        self.executable_aliases.insert(alias, canonical.clone());
        Ok(canonical)
    }
}

/// Host-side process effect provider.
pub trait ProcessSpawnProvider: fmt::Debug + Send + Sync {
    fn name(&self) -> &str;

    /// Allocation-free, side-effect-free request admission.
    ///
    /// Callers invoke this before journal reservation or request hashing so an
    /// oversized request cannot force an unbounded clone/serialization before
    /// the provider's policy sees it. Implementations must not perform I/O or
    /// mutate provider state here; live preparation remains journaled.
    fn preflight_request(&self, _request: &ProcessSpawnRequest) -> Result<(), ProcessSpawnError> {
        Ok(())
    }

    /// Resolve policy-owned aliases into a canonical request before replay or
    /// live dispatch. The default provider has no alias vocabulary.
    fn prepare_request(
        &self,
        request: &ProcessSpawnRequest,
    ) -> Result<ProcessSpawnRequest, ProcessSpawnError> {
        Ok(request.clone())
    }

    /// Perform one operation using only explicitly presented capabilities.
    fn perform(
        &self,
        request: &ProcessSpawnRequest,
        granted: &[ProcessSpawnCapability],
    ) -> ProcessSpawnOutcome;

    /// Perform while honoring a live cancellation/deadline/authority control.
    ///
    /// Providers whose work can block must override this method and poll the
    /// control through every blocking phase. The default is suitable only for
    /// already-bounded, synchronous providers.
    fn perform_controlled(
        &self,
        request: &ProcessSpawnRequest,
        granted: &[ProcessSpawnCapability],
        control: Arc<dyn ProcessSpawnControl>,
    ) -> ProcessSpawnOutcome {
        control.checkpoint()?;
        self.perform(request, granted)
    }

    /// Abandon one engine-owned lifecycle handle during execution teardown.
    /// This is compensating containment, not a guest-requested signal: native
    /// providers must synchronously revoke ownership and reap any live child
    /// even when the signed guest policy does not grant `Kill`. The caller
    /// must reserve and commit the returned typed outcome in the global
    /// host-effect journal.
    fn cleanup_handle(&self, handle: &str) -> ProcessSpawnOutcome;
}

/// Default provider: no request can cause a process effect.
#[derive(Debug, Clone, Copy, Default)]
pub struct DenyAllProcessSpawn;

impl ProcessSpawnProvider for DenyAllProcessSpawn {
    fn name(&self) -> &str {
        "deny-all-process-spawn"
    }

    fn perform(
        &self,
        _request: &ProcessSpawnRequest,
        _granted: &[ProcessSpawnCapability],
    ) -> ProcessSpawnOutcome {
        Err(ProcessSpawnError::Denied {
            reason: "no native process provider installed; fail-closed deny".to_string(),
        })
    }

    fn cleanup_handle(&self, _handle: &str) -> ProcessSpawnOutcome {
        Ok(ProcessSpawnResponse::Cleaned { was_present: false })
    }
}

#[must_use]
pub fn process_capability_granted(
    granted: &[ProcessSpawnCapability],
    required: ProcessSpawnCapability,
) -> bool {
    granted.contains(&required)
}

#[derive(Debug)]
struct ActiveChildPermit {
    active: Arc<AtomicUsize>,
}

impl Drop for ActiveChildPermit {
    fn drop(&mut self) {
        self.active.fetch_sub(1, Ordering::AcqRel);
    }
}

struct ActiveWatchdogPermit {
    active: Arc<AtomicUsize>,
}

impl Drop for ActiveWatchdogPermit {
    fn drop(&mut self) {
        self.active.fetch_sub(1, Ordering::AcqRel);
    }
}

struct CapturedOutput {
    bytes: Vec<u8>,
    overflowed: bool,
    maximum: u64,
}

impl fmt::Debug for CapturedOutput {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("CapturedOutput")
            .field("byte_count", &self.bytes.len())
            .field("overflowed", &self.overflowed)
            .field("maximum", &self.maximum)
            .finish()
    }
}

#[derive(Debug)]
struct OutputDrain {
    cancel: Arc<AtomicBool>,
    thread: JoinHandle<std::io::Result<CapturedOutput>>,
}

/// Command for the bounded background stdin writer of a lifecycle spawn
/// (bd-m42c2).
#[derive(Debug)]
enum StdinWriterCommand {
    Write(Vec<u8>),
    Close,
}

/// Handle to the dedicated thread that owns a lifecycle child's stdin pipe.
/// Guest `write` calls enqueue bounded chunks and return immediately; the
/// writer thread absorbs pipe backpressure off the interpreter. Dropping or
/// `Close` closes the pipe, delivering EOF to the child. Total accepted
/// bytes stay bounded by the policy `max_stdin_bytes` limit enforced at the
/// `write_stdin` boundary.
#[derive(Debug)]
struct StdinWriter {
    tx: Option<Sender<StdinWriterCommand>>,
}

#[derive(Debug)]
struct RunningChild {
    child: Child,
    /// One-shot upfront writer owned by the Run lane (`join_stdin_writer`).
    /// Lifecycle spawns move this into [`StdinWriter`] instead.
    stdin: Option<ChildStdin>,
    stdin_writer: Option<StdinWriter>,
    stdout: Option<OutputDrain>,
    stderr: Option<OutputDrain>,
    #[cfg(unix)]
    process_group: rustix::process::Pid,
    started: Instant,
    stdin_written: u64,
    watchdog_cancel: Option<SyncSender<()>>,
    _permit: ActiveChildPermit,
}

#[derive(Debug)]
enum LifecycleChild {
    Running(RunningChild),
    Terminal(ProcessSpawnOutcome),
}

type ChildMap = BTreeMap<String, LifecycleChild>;

/// Native, policy-gated process provider.
///
/// Handles contain a provider-instance scope and monotonic nonce, never a PID.
/// A detached watchdog reaps lifecycle children at the policy runtime deadline
/// even if the guest never sends `wait` or `kill`.
pub struct NativeProcessSpawn {
    policy: ProcessSpawnPolicy,
    scope: String,
    next_handle: AtomicU64,
    active_children: Arc<AtomicUsize>,
    active_watchdogs: Arc<AtomicUsize>,
    children: Arc<Mutex<ChildMap>>,
}

impl fmt::Debug for NativeProcessSpawn {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("NativeProcessSpawn")
            .field("policy", &self.policy)
            .field("scope", &"<opaque>")
            .field("next_handle", &self.next_handle.load(Ordering::Relaxed))
            .field(
                "active_children",
                &self.active_children.load(Ordering::Relaxed),
            )
            .field(
                "active_watchdogs",
                &self.active_watchdogs.load(Ordering::Relaxed),
            )
            .field(
                "terminal_children",
                &lock_unpoison(&self.children)
                    .values()
                    .filter(|child| matches!(child, LifecycleChild::Terminal(_)))
                    .count(),
            )
            .finish_non_exhaustive()
    }
}

impl NativeProcessSpawn {
    /// Install a policy after validating its canonical jail and fixed fields.
    pub fn new(policy: ProcessSpawnPolicy) -> Result<Self, ProcessSpawnError> {
        #[cfg(not(any(target_os = "linux", target_os = "freebsd")))]
        {
            let _ = policy;
            Err(ProcessSpawnError::NotImplemented {
                what: "native process containment requires descriptor-pinned executable identity and process-group backends"
                    .to_string(),
            })
        }
        #[cfg(any(target_os = "linux", target_os = "freebsd"))]
        {
            validate_policy(&policy)?;
            Ok(Self {
                policy,
                scope: fresh_scope(),
                next_handle: AtomicU64::new(0),
                active_children: Arc::new(AtomicUsize::new(0)),
                active_watchdogs: Arc::new(AtomicUsize::new(0)),
                children: Arc::new(Mutex::new(BTreeMap::new())),
            })
        }
    }

    #[must_use]
    pub fn policy(&self) -> &ProcessSpawnPolicy {
        &self.policy
    }

    fn reserve_child(&self) -> Result<ActiveChildPermit, ProcessSpawnError> {
        let maximum = usize::try_from(self.policy.limits.max_children).unwrap_or(usize::MAX);
        loop {
            let current = self.active_children.load(Ordering::Acquire);
            if current >= maximum {
                return Err(ProcessSpawnError::LimitExceeded {
                    limit: "children".to_string(),
                    actual: u64::try_from(current.saturating_add(1)).unwrap_or(u64::MAX),
                    maximum: self.policy.limits.max_children,
                });
            }
            if self
                .active_children
                .compare_exchange_weak(current, current + 1, Ordering::AcqRel, Ordering::Acquire)
                .is_ok()
            {
                return Ok(ActiveChildPermit {
                    active: Arc::clone(&self.active_children),
                });
            }
        }
    }

    fn preflight_launch(&self, launch: &ProcessLaunch) -> Result<u64, ProcessSpawnError> {
        let limits = &self.policy.limits;
        let executable_bytes = u64::try_from(launch.executable.len()).unwrap_or(u64::MAX);
        enforce_limit(
            "executable_path_bytes",
            executable_bytes,
            limits.max_executable_path_bytes,
        )?;
        if launch.executable.contains('\0') {
            return Err(policy_error(
                "invalid_executable",
                "executable path contains a NUL byte",
            ));
        }

        let argv_count = u64::try_from(launch.argv.len()).unwrap_or(u64::MAX);
        enforce_limit("argv_count", argv_count, limits.max_argv_count)?;
        let argv_bytes = launch.argv.iter().try_fold(0_u64, |total, argument| {
            if argument.contains('\0') {
                return Err(policy_error("invalid_argv", "argv contains a NUL byte"));
            }
            Ok(total.saturating_add(u64::try_from(argument.len()).unwrap_or(u64::MAX)))
        })?;
        enforce_limit("argv_bytes", argv_bytes, limits.max_argv_bytes)?;

        let env_count = self.policy.fixed_env.len().saturating_add(launch.env.len());
        let env_count = u64::try_from(env_count).unwrap_or(u64::MAX);
        enforce_limit("env_count", env_count, limits.max_env_count)?;
        let fixed_env_bytes = self
            .policy
            .fixed_env
            .iter()
            .fold(0_u64, |total, (key, value)| {
                total
                    .saturating_add(u64::try_from(key.len()).unwrap_or(u64::MAX))
                    .saturating_add(u64::try_from(value.len()).unwrap_or(u64::MAX))
            });
        let env_bytes = launch.env.iter().try_fold(
            fixed_env_bytes,
            |total, (key, value)| -> Result<u64, ProcessSpawnError> {
                validate_env_pair(key, value)?;
                if !self.policy.allowed_env_keys.contains(key) {
                    return Err(policy_error(
                        "env_key_denied",
                        format!("environment key {key} is not allowed"),
                    ));
                }
                if self.policy.fixed_env.contains_key(key) {
                    return Err(policy_error(
                        "fixed_env_override",
                        format!("environment key {key} is fixed by policy"),
                    ));
                }
                Ok(total
                    .saturating_add(u64::try_from(key.len()).unwrap_or(u64::MAX))
                    .saturating_add(u64::try_from(value.len()).unwrap_or(u64::MAX)))
            },
        )?;
        enforce_limit("env_bytes", env_bytes, limits.max_env_bytes)?;

        let cwd_bytes = launch
            .cwd
            .as_ref()
            .map_or(0, |cwd| u64::try_from(cwd.len()).unwrap_or(u64::MAX));
        enforce_limit("cwd_bytes", cwd_bytes, limits.max_cwd_bytes)?;
        if launch.cwd.as_ref().is_some_and(|cwd| cwd.contains('\0')) {
            return Err(policy_error(
                "invalid_cwd",
                "working directory contains a NUL byte",
            ));
        }

        let prelaunch_bytes = executable_bytes
            .saturating_add(argv_bytes)
            .saturating_add(env_bytes)
            .saturating_add(cwd_bytes);
        enforce_limit(
            "prelaunch_bytes",
            prelaunch_bytes,
            limits.max_prelaunch_bytes,
        )?;
        Ok(prelaunch_bytes)
    }

    fn preflight_process_request(
        &self,
        request: &ProcessSpawnRequest,
    ) -> Result<(), ProcessSpawnError> {
        let request_bytes = match request {
            ProcessSpawnRequest::Run { launch, stdin, .. } => {
                let prelaunch_bytes = self.preflight_launch(launch)?;
                let stdin_bytes = u64::try_from(stdin.len()).unwrap_or(u64::MAX);
                enforce_limit(
                    "stdin_bytes",
                    stdin_bytes,
                    self.policy.limits.max_stdin_bytes,
                )?;
                prelaunch_bytes.saturating_add(stdin_bytes)
            }
            ProcessSpawnRequest::Spawn { launch } => self.preflight_launch(launch)?,
            ProcessSpawnRequest::WriteStdin { handle, data } => {
                let data_bytes = u64::try_from(data.len()).unwrap_or(u64::MAX);
                enforce_limit(
                    "stdin_bytes",
                    data_bytes,
                    self.policy.limits.max_stdin_bytes,
                )?;
                u64::try_from(handle.len())
                    .unwrap_or(u64::MAX)
                    .saturating_add(data_bytes)
            }
            ProcessSpawnRequest::CloseStdin { handle }
            | ProcessSpawnRequest::Wait { handle, .. }
            | ProcessSpawnRequest::Kill { handle, .. }
            | ProcessSpawnRequest::Cleanup { handle } => {
                u64::try_from(handle.len()).unwrap_or(u64::MAX)
            }
        };
        enforce_limit(
            "request_raw_bytes",
            request_bytes,
            self.policy.limits.max_request_bytes,
        )?;
        let mut counter = CountingWriter::default();
        serde_json::to_writer(&mut counter, request).map_err(|error| {
            ProcessSpawnError::InvalidState {
                detail: format!("typed process request could not be size-counted: {error}"),
            }
        })?;
        enforce_limit(
            "request_bytes",
            counter.bytes,
            self.policy.limits.max_request_bytes,
        )
    }

    fn validate_launch_controlled(
        &self,
        launch: &ProcessLaunch,
        control: &dyn ProcessSpawnControl,
    ) -> Result<ValidatedLaunch, ProcessSpawnError> {
        self.preflight_launch(launch)?;
        control.checkpoint()?;
        if launch.shell && !self.policy.allow_shell {
            return Err(policy_error(
                "shell_denied",
                "shell execution is disabled by policy",
            ));
        }
        if launch.shell
            && (launch.argv.len() != 2 || launch.argv.first().map(String::as_str) != Some("-c"))
        {
            return Err(policy_error(
                "shell_protocol",
                "shell execution requires exact argv [\"-c\", <script>]",
            ));
        }
        for mode in [launch.stdio.stdin, launch.stdio.stdout, launch.stdio.stderr] {
            if !self.policy.allowed_stdio.contains(&mode) {
                return Err(policy_error(
                    "stdio_denied",
                    format!("stdio mode {mode:?} is not allowed"),
                ));
            }
        }

        let argv_count = u64::try_from(launch.argv.len()).unwrap_or(u64::MAX);
        enforce_limit("argv_count", argv_count, self.policy.limits.max_argv_count)?;
        let argv_bytes = launch.argv.iter().try_fold(0_u64, |total, argument| {
            if argument.contains('\0') {
                return Err(policy_error("invalid_argv", "argv contains a NUL byte"));
            }
            Ok(total.saturating_add(u64::try_from(argument.len()).unwrap_or(u64::MAX)))
        })?;
        enforce_limit("argv_bytes", argv_bytes, self.policy.limits.max_argv_bytes)?;

        let executable =
            std::fs::canonicalize(&launch.executable).map_err(executable_canonicalize_error)?;
        control.checkpoint()?;
        let executable_string = path_string(&executable)?;
        if executable_string != launch.executable {
            return Err(policy_error(
                "noncanonical_executable",
                "request executable must be its exact canonical path",
            ));
        }
        let expected_digest = self
            .policy
            .allowed_executables
            .get(&executable_string)
            .ok_or_else(|| {
                policy_error(
                    "executable_denied",
                    format!("{executable_string} is not allowlisted"),
                )
            })?;
        let cwd_root = PathBuf::from(&self.policy.jailed_cwd_root);
        let requested_cwd = launch.cwd.as_deref().map_or_else(
            || cwd_root.clone(),
            |cwd| {
                let path = Path::new(cwd);
                if path.is_absolute() {
                    path.to_path_buf()
                } else {
                    cwd_root.join(path)
                }
            },
        );
        let cwd = canonical_directory(&requested_cwd, "canonicalize process cwd")?;
        if !cwd.starts_with(&cwd_root) {
            return Err(policy_error(
                "cwd_escape",
                format!(
                    "working directory {} escapes jail {}",
                    cwd.display(),
                    cwd_root.display()
                ),
            ));
        }

        let mut env = self.policy.fixed_env.clone();
        for (key, value) in &launch.env {
            validate_env_pair(key, value)?;
            if !self.policy.allowed_env_keys.contains(key) {
                return Err(policy_error(
                    "env_key_denied",
                    format!("environment key {key} is not allowed"),
                ));
            }
            if self.policy.fixed_env.contains_key(key) {
                return Err(policy_error(
                    "fixed_env_override",
                    format!("environment key {key} is fixed by policy"),
                ));
            }
            env.insert(key.clone(), value.clone());
        }

        let executable_file = open_verified_executable(
            &executable,
            expected_digest,
            &executable_string,
            self.policy.limits.max_executable_bytes,
            control,
        )?;

        Ok(ValidatedLaunch {
            executable,
            executable_file: Some(executable_file),
            argv: launch.argv.clone(),
            env,
            cwd,
            stdio: launch.stdio,
        })
    }

    #[cfg(test)]
    fn validate_launch(
        &self,
        launch: &ProcessLaunch,
    ) -> Result<ValidatedLaunch, ProcessSpawnError> {
        self.validate_launch_controlled(launch, &UnrestrictedProcessSpawnControl)
    }

    fn prepare_launch(&self, launch: &ProcessLaunch) -> Result<ProcessLaunch, ProcessSpawnError> {
        if launch.shell {
            if !self.policy.allow_shell {
                return Err(policy_error(
                    "shell_denied",
                    "shell execution is disabled by policy",
                ));
            }
            let alias = self
                .policy
                .shell_executable_alias
                .as_deref()
                .ok_or_else(|| {
                    policy_error(
                        "shell_not_configured",
                        "policy has no signed shell executable alias",
                    )
                })?;
            let shell = self.policy.executable_aliases.get(alias).ok_or_else(|| {
                policy_error(
                    "shell_alias_denied",
                    format!("signed shell alias {alias} is not authorized"),
                )
            })?;
            if launch.executable.is_empty() && launch.argv.len() == 1 {
                let command = &launch.argv[0];
                if command.is_empty() {
                    return Err(policy_error(
                        "shell_caller_selection",
                        "shell request command must not be empty",
                    ));
                }
                if command.contains('\0') {
                    return Err(policy_error(
                        "invalid_shell_command",
                        "shell command contains a NUL byte",
                    ));
                }
                let mut prepared = launch.clone();
                prepared.executable.clone_from(shell);
                prepared.argv = vec!["-c".to_string(), command.to_string()];
                return Ok(prepared);
            }
            // Preparation is idempotent because the process handler prepares
            // before calling a provider that independently prepares again.
            if &launch.executable == shell
                && launch.argv.len() == 2
                && launch.argv.first().map(String::as_str) == Some("-c")
            {
                return Ok(launch.clone());
            }
            return Err(policy_error(
                "shell_caller_selection",
                "caller may not select a shell executable or argv shape",
            ));
        }
        let executable = Path::new(&launch.executable);
        if executable.is_absolute() {
            return Ok(launch.clone());
        }
        validate_executable_alias(&launch.executable)?;
        let resolved = self
            .policy
            .executable_aliases
            .get(&launch.executable)
            .ok_or_else(|| {
                policy_error(
                    "executable_alias_denied",
                    format!(
                        "bare executable alias {} is not signed into policy",
                        launch.executable
                    ),
                )
            })?;
        let mut prepared = launch.clone();
        prepared.executable.clone_from(resolved);
        Ok(prepared)
    }

    fn prepare_process_request(
        &self,
        request: &ProcessSpawnRequest,
    ) -> Result<ProcessSpawnRequest, ProcessSpawnError> {
        self.preflight_process_request(request)?;
        let prepared = match request {
            ProcessSpawnRequest::Run {
                launch,
                stdin,
                timeout_millis,
            } => ProcessSpawnRequest::Run {
                launch: self.prepare_launch(launch)?,
                stdin: stdin.clone(),
                timeout_millis: *timeout_millis,
            },
            ProcessSpawnRequest::Spawn { launch } => ProcessSpawnRequest::Spawn {
                launch: self.prepare_launch(launch)?,
            },
            ProcessSpawnRequest::WriteStdin { handle, data } => ProcessSpawnRequest::WriteStdin {
                handle: handle.clone(),
                data: data.clone(),
            },
            ProcessSpawnRequest::CloseStdin { handle } => ProcessSpawnRequest::CloseStdin {
                handle: handle.clone(),
            },
            ProcessSpawnRequest::Wait {
                handle,
                timeout_millis,
            } => ProcessSpawnRequest::Wait {
                handle: handle.clone(),
                timeout_millis: *timeout_millis,
            },
            ProcessSpawnRequest::Kill { handle, signal } => ProcessSpawnRequest::Kill {
                handle: handle.clone(),
                signal: *signal,
            },
            ProcessSpawnRequest::Cleanup { handle } => ProcessSpawnRequest::Cleanup {
                handle: handle.clone(),
            },
        };
        self.preflight_process_request(&prepared)?;
        Ok(prepared)
    }

    fn spawn_validated(
        &self,
        launch: ValidatedLaunch,
        permit: ActiveChildPermit,
    ) -> Result<RunningChild, ProcessSpawnError> {
        let executable_file =
            launch
                .executable_file
                .as_ref()
                .ok_or_else(|| ProcessSpawnError::InvalidState {
                    detail: "validated launch is missing its verified executable file".to_string(),
                })?;
        let mut command = Command::new(pinned_executable_path(executable_file)?);
        #[cfg(unix)]
        command.arg0(&launch.executable);
        command
            .args(&launch.argv)
            .current_dir(&launch.cwd)
            .env_clear()
            .envs(&launch.env)
            .stdin(to_stdio(launch.stdio.stdin))
            .stdout(to_stdio(launch.stdio.stdout))
            .stderr(to_stdio(launch.stdio.stderr));
        #[cfg(unix)]
        command.process_group(0);
        let mut child = command.spawn().map_err(executable_spawn_error)?;
        #[cfg(unix)]
        let process_group = rustix::process::Pid::from_child(&child);

        let stdout = match child.stdout.take() {
            Some(stdout) => {
                match spawn_reader(stdout, self.policy.limits.max_output_bytes, "stdout") {
                    Ok(reader) => Some(reader),
                    Err(error) => {
                        #[cfg(unix)]
                        let _ = terminate_process_group_id(process_group);
                        kill_and_reap(&mut child);
                        return Err(error);
                    }
                }
            }
            None => None,
        };
        let stderr = match child.stderr.take() {
            Some(stderr) => {
                match spawn_reader(stderr, self.policy.limits.max_output_bytes, "stderr") {
                    Ok(reader) => Some(reader),
                    Err(error) => {
                        #[cfg(unix)]
                        let _ = terminate_process_group_id(process_group);
                        kill_and_reap(&mut child);
                        if let Some(reader) = stdout {
                            let _ = join_reader(Some(reader), "stdout");
                        }
                        return Err(error);
                    }
                }
            }
            None => None,
        };

        Ok(RunningChild {
            stdin: child.stdin.take(),
            stdin_writer: None,
            child,
            stdout,
            stderr,
            #[cfg(unix)]
            process_group,
            started: Instant::now(),
            stdin_written: 0,
            watchdog_cancel: None,
            _permit: permit,
        })
    }

    fn launch_controlled(
        &self,
        launch: &ProcessLaunch,
        control: &dyn ProcessSpawnControl,
    ) -> Result<RunningChild, ProcessSpawnError> {
        let launch = self.validate_launch_controlled(launch, control)?;
        let permit = self.reserve_child()?;
        control.checkpoint()?;
        let mut running = self.spawn_validated(launch, permit)?;
        if let Err(error) = control.checkpoint() {
            let _ = terminate_remaining_process_group(&running);
            kill_and_reap(&mut running.child);
            let _ = collect_outputs(running);
            return Err(error);
        }
        Ok(running)
    }

    fn run_controlled(
        &self,
        launch: &ProcessLaunch,
        stdin: &[u8],
        timeout_millis: Option<u64>,
        control: &dyn ProcessSpawnControl,
    ) -> ProcessSpawnOutcome {
        enforce_limit(
            "stdin_bytes",
            u64::try_from(stdin.len()).unwrap_or(u64::MAX),
            self.policy.limits.max_stdin_bytes,
        )?;
        if !stdin.is_empty() && launch.stdio.stdin != ProcessStdioMode::Pipe {
            return Err(policy_error(
                "stdin_not_piped",
                "run input requires piped stdin",
            ));
        }
        let mut running = self.launch_controlled(launch, control)?;
        let stdin_writer = if stdin.is_empty() {
            drop(running.stdin.take());
            None
        } else if let Some(child_stdin) = running.stdin.take() {
            match spawn_stdin_writer(child_stdin, stdin.to_vec()) {
                Ok(writer) => Some(writer),
                Err(error) => {
                    let _ = terminate_remaining_process_group(&running);
                    kill_and_reap(&mut running.child);
                    let _ = collect_outputs(running);
                    return Err(error);
                }
            }
        } else {
            None
        };
        let timeout = effective_timeout(timeout_millis, self.policy.limits.max_runtime_millis);
        let process_result = wait_and_collect_controlled(running, timeout, control);
        let stdin_result = join_stdin_writer(stdin_writer);
        let (exit, stdout, stderr) = match process_result {
            Ok(result) => {
                stdin_result?;
                result
            }
            Err(error) => {
                // Timeout/cleanup is primary. Reaping closes the pipe and
                // guarantees the writer has stopped before this returns.
                let _ = stdin_result;
                return Err(error);
            }
        };
        Ok(ProcessSpawnResponse::Run {
            exit,
            stdout,
            stderr,
        })
    }

    fn spawn_controlled(
        &self,
        launch: &ProcessLaunch,
        control: Arc<dyn ProcessSpawnControl>,
    ) -> ProcessSpawnOutcome {
        let mut running = self.launch_controlled(launch, control.as_ref())?;
        // bd-m42c2: lifecycle spawns hand the stdin pipe to a dedicated
        // bounded writer thread so guest write()/end() never block the
        // interpreter on pipe backpressure.
        if launch.stdio.stdin == ProcessStdioMode::Pipe
            && let Some(child_stdin) = running.stdin.take()
        {
            running.stdin_writer = Some(spawn_lifecycle_stdin_writer(child_stdin));
        }
        let nonce = self.next_handle.fetch_add(1, Ordering::Relaxed);
        let handle = format!("ps-{}-{nonce:016x}", self.scope);
        lock_unpoison(&self.children).insert(handle.clone(), LifecycleChild::Running(running));
        match self.start_watchdog(handle.clone(), control) {
            Ok(cancel) => {
                let mut children = lock_unpoison(&self.children);
                match children.get_mut(&handle) {
                    Some(LifecycleChild::Running(running)) => {
                        running.watchdog_cancel = Some(cancel);
                    }
                    Some(LifecycleChild::Terminal(_)) => {
                        // The deadline won the race, but the terminal outcome
                        // remains owned by this now-visible handle for Wait.
                        drop(cancel);
                    }
                    None => {
                        return Err(ProcessSpawnError::InvalidState {
                            detail: "process watchdog lost lifecycle registration".to_string(),
                        });
                    }
                }
            }
            Err(error) => {
                let running = lock_unpoison(&self.children).remove(&handle);
                if let Some(LifecycleChild::Running(mut running)) = running {
                    let _ = terminate_remaining_process_group(&running);
                    kill_and_reap(&mut running.child);
                    let (partial_stdout, partial_stderr) = collect_outputs_lossy(running);
                    return Err(ProcessSpawnError::PartialOutputFailed {
                        failure: Box::new(error),
                        signal: None,
                        partial_stdout,
                        partial_stderr,
                    });
                }
                return Err(error);
            }
        }
        Ok(ProcessSpawnResponse::Spawned { handle })
    }

    fn start_watchdog(
        &self,
        handle: String,
        control: Arc<dyn ProcessSpawnControl>,
    ) -> Result<SyncSender<()>, ProcessSpawnError> {
        let children = Arc::downgrade(&self.children);
        let active_watchdogs = Arc::clone(&self.active_watchdogs);
        let timeout = Duration::from_millis(self.policy.limits.max_runtime_millis);
        let max_tombstones = usize::try_from(self.policy.limits.max_children)
            .unwrap_or(usize::MAX)
            .max(1);
        let (cancel, cancelled) = sync_channel(1);
        self.active_watchdogs.fetch_add(1, Ordering::AcqRel);
        let spawned = thread::Builder::new()
            .name("franken-process-watchdog".to_string())
            .spawn(move || {
                let _permit = ActiveWatchdogPermit {
                    active: active_watchdogs,
                };
                let deadline = Instant::now().checked_add(timeout);
                let stop_error = loop {
                    if let Err(error) = control.checkpoint() {
                        break Some(error);
                    }
                    let Some(remaining) =
                        deadline.and_then(|value| value.checked_duration_since(Instant::now()))
                    else {
                        break None;
                    };
                    let poll = remaining.min(Duration::from_millis(2));
                    match cancelled.recv_timeout(poll) {
                        Ok(()) => return,
                        Err(RecvTimeoutError::Timeout) => {}
                        Err(RecvTimeoutError::Disconnected) => break None,
                    }
                };
                let Some(children) = Weak::upgrade(&children) else {
                    return;
                };
                // Keep ownership inside the provider map while reaping. Drop
                // and Wait block on this same lock, so neither can observe an
                // empty ownership gap and let the OS child escape.
                let mut children = lock_unpoison(&children);
                let Some(LifecycleChild::Running(mut running)) = children.remove(&handle) else {
                    return;
                };
                let outcome = match running.child.try_wait() {
                    Ok(Some(status)) => collect_outputs_controlled(running, control.as_ref()).map(
                        |(stdout, stderr)| ProcessSpawnResponse::Waited {
                            exit: exit_from_status(status),
                            stdout,
                            stderr,
                        },
                    ),
                    Ok(None) => {
                        let _ = terminate_remaining_process_group(&running);
                        let signal = kill_and_reap_capture(&mut running.child);
                        let runtime_millis = elapsed_millis(running.started);
                        let (partial_stdout, partial_stderr) = collect_outputs_lossy(running);
                        Err(
                            stop_error.unwrap_or(ProcessSpawnError::PartialOutputFailed {
                                failure: Box::new(ProcessSpawnError::TimedOut { runtime_millis }),
                                signal,
                                partial_stdout,
                                partial_stderr,
                            }),
                        )
                    }
                    Err(error) => {
                        let _ = terminate_remaining_process_group(&running);
                        kill_and_reap(&mut running.child);
                        let (partial_stdout, partial_stderr) = collect_outputs_lossy(running);
                        Err(ProcessSpawnError::PartialOutputFailed {
                            failure: Box::new(ProcessSpawnError::Io {
                                operation: "watchdog poll child".to_string(),
                                detail: error.to_string(),
                            }),
                            signal: None,
                            partial_stdout,
                            partial_stderr,
                        })
                    }
                };
                children.insert(handle, LifecycleChild::Terminal(outcome));
                trim_terminal_children(&mut children, max_tombstones);
            });
        if let Err(error) = spawned {
            self.active_watchdogs.fetch_sub(1, Ordering::AcqRel);
            return Err(ProcessSpawnError::Io {
                operation: "start process watchdog".to_string(),
                detail: error.to_string(),
            });
        }
        Ok(cancel)
    }

    fn write_stdin(&self, handle: &str, data: &[u8]) -> ProcessSpawnOutcome {
        let requested = u64::try_from(data.len()).unwrap_or(u64::MAX);
        let mut children = lock_unpoison(&self.children);
        let running = match children.get_mut(handle) {
            Some(LifecycleChild::Running(running)) => running,
            Some(LifecycleChild::Terminal(outcome)) => {
                return terminal_operation_error(handle, outcome);
            }
            None => return Err(unknown_handle(handle)),
        };
        if running.started.elapsed() >= Duration::from_millis(self.policy.limits.max_runtime_millis)
        {
            let Some(LifecycleChild::Running(mut running)) = children.remove(handle) else {
                return Err(unknown_handle(handle));
            };
            drop(children);
            let _ = terminate_remaining_process_group(&running);
            let signal = kill_and_reap_capture(&mut running.child);
            let elapsed = elapsed_millis(running.started);
            let (partial_stdout, partial_stderr) = collect_outputs_lossy(running);
            return Err(ProcessSpawnError::PartialOutputFailed {
                failure: Box::new(ProcessSpawnError::TimedOut {
                    runtime_millis: elapsed,
                }),
                signal,
                partial_stdout,
                partial_stderr,
            });
        }
        // bd-m42c2: the cumulative accepted-byte bound is the backpressure
        // contract. Bytes are accounted at accept time even though the
        // dedicated writer thread may still be draining the pipe, so a guest
        // can never enqueue more than `max_stdin_bytes` in total.
        let total = running.stdin_written.saturating_add(requested);
        enforce_limit("stdin_bytes", total, self.policy.limits.max_stdin_bytes)?;
        let Some(writer) = running.stdin_writer.as_mut() else {
            return Err(ProcessSpawnError::InvalidState {
                detail: format!("stdin is not writable for handle {handle}"),
            });
        };
        let Some(tx) = writer.tx.as_ref() else {
            return Err(ProcessSpawnError::InvalidState {
                detail: format!("stdin is already closed or was not piped for handle {handle}"),
            });
        };
        if requested != 0 && tx.send(StdinWriterCommand::Write(data.to_vec())).is_err() {
            writer.tx = None;
            return Err(ProcessSpawnError::Io {
                operation: "write stdin".to_string(),
                detail: "stdin writer thread is no longer available".to_string(),
            });
        }
        running.stdin_written = total;
        Ok(ProcessSpawnResponse::StdinWritten {
            bytes_written: requested,
        })
    }

    fn close_stdin(&self, handle: &str) -> ProcessSpawnOutcome {
        let mut children = lock_unpoison(&self.children);
        let running = match children.get_mut(handle) {
            Some(LifecycleChild::Running(running)) => running,
            Some(LifecycleChild::Terminal(outcome)) => {
                return terminal_operation_error(handle, outcome);
            }
            None => return Err(unknown_handle(handle)),
        };
        // bd-m42c2: `end()` closes the pipe via the writer thread, delivering
        // EOF to the child. Already-closed or never-piped stdin stays a
        // typed InvalidState refusal.
        match running.stdin_writer.as_mut().and_then(|w| w.tx.take()) {
            Some(tx) => {
                // A failed send means the writer already exited (pipe or
                // child gone); the EOF outcome is identical either way.
                let _ = tx.send(StdinWriterCommand::Close);
            }
            None => {
                return Err(ProcessSpawnError::InvalidState {
                    detail: format!("stdin is already closed or was not piped for handle {handle}"),
                });
            }
        }
        Ok(ProcessSpawnResponse::StdinClosed)
    }

    fn wait_controlled(
        &self,
        handle: &str,
        timeout_millis: Option<u64>,
        control: &dyn ProcessSpawnControl,
    ) -> ProcessSpawnOutcome {
        control.checkpoint()?;
        let state = lock_unpoison(&self.children)
            .remove(handle)
            .ok_or_else(|| unknown_handle(handle))?;
        let running = match state {
            LifecycleChild::Running(running) => running,
            LifecycleChild::Terminal(outcome) => return outcome,
        };
        let remaining_policy_millis = self
            .policy
            .limits
            .max_runtime_millis
            .saturating_sub(elapsed_millis(running.started));
        let timeout = effective_timeout(timeout_millis, remaining_policy_millis);
        let (exit, stdout, stderr) = wait_and_collect_controlled(running, timeout, control)?;
        Ok(ProcessSpawnResponse::Waited {
            exit,
            stdout,
            stderr,
        })
    }

    fn kill_controlled(
        &self,
        handle: &str,
        signal: ProcessSignal,
        control: &dyn ProcessSpawnControl,
    ) -> ProcessSpawnOutcome {
        if !self.policy.allowed_signals.contains(&signal) {
            return Err(policy_error(
                "signal_denied",
                format!("signal {} is not allowed", signal.as_str()),
            ));
        }
        if signal != ProcessSignal::Kill {
            #[cfg(not(unix))]
            {
                let _ = signal;
                return Err(ProcessSpawnError::NotImplemented {
                    what: format!(
                        "signal {} requires unix process-group signaling",
                        signal.as_str()
                    ),
                });
            }
        }
        let state = lock_unpoison(&self.children)
            .remove(handle)
            .ok_or_else(|| unknown_handle(handle))?;
        let mut running = match state {
            LifecycleChild::Running(running) => running,
            LifecycleChild::Terminal(outcome) => return terminal_operation_error(handle, &outcome),
        };
        let exited = match running.child.try_wait() {
            Ok(status) => status.is_some(),
            Err(error) => {
                let _ = terminate_remaining_process_group(&running);
                kill_and_reap(&mut running.child);
                let _ = collect_outputs(running);
                return Err(ProcessSpawnError::Io {
                    operation: "poll before kill".to_string(),
                    detail: error.to_string(),
                });
            }
        };
        if !exited {
            match signal {
                ProcessSignal::Kill => {
                    let group_result = terminate_remaining_process_group(&running);
                    let child_result = running.child.kill();
                    if let (Err(group_error), Err(child_error)) = (group_result, child_result) {
                        // A process may exit between `try_wait` and signalling.
                        // Always reap before reporting the failed containment
                        // attempt.
                        let _ = running.child.wait();
                        let _ = collect_outputs(running);
                        return Err(ProcessSpawnError::Io {
                            operation: "kill process group and child".to_string(),
                            detail: format!("{group_error}; direct child fallback: {child_error}"),
                        });
                    }
                }
                ProcessSignal::Terminate | ProcessSignal::Interrupt => {
                    // bd-m42c2: TERM/INT go to the child's private process
                    // group via the same rustix surface as containment
                    // teardown; std's `Child::kill` is SIGKILL-only.
                    #[cfg(unix)]
                    if let Err(error) =
                        signal_process_group_id(running.process_group, rustix_signal(signal))
                    {
                        let _ = running.child.wait();
                        let _ = collect_outputs(running);
                        return Err(error);
                    }
                    #[cfg(not(unix))]
                    unreachable!("non-unix TERM/INT was refused above");
                }
            }
        }
        let status = match running.child.wait() {
            Ok(status) => status,
            Err(error) => {
                let _ = terminate_remaining_process_group(&running);
                kill_and_reap(&mut running.child);
                let _ = collect_outputs(running);
                return Err(ProcessSpawnError::Io {
                    operation: "reap after kill".to_string(),
                    detail: error.to_string(),
                });
            }
        };
        let (stdout, stderr) = collect_outputs_controlled(running, control)?;
        let outcome = Ok(ProcessSpawnResponse::Killed {
            signal,
            exit: exit_from_status(status),
            stdout,
            stderr,
        });
        // bd-m42c2: the pending lifecycle `Wait` turn must observe the kill
        // outcome instead of an unknown handle, so the terminal record stays
        // addressable under the same handle (mirroring watchdog completion).
        {
            let mut children = lock_unpoison(&self.children);
            children.insert(
                handle.to_string(),
                LifecycleChild::Terminal(outcome.clone()),
            );
            trim_terminal_children(
                &mut children,
                usize::try_from(self.policy.limits.max_children)
                    .unwrap_or(usize::MAX)
                    .max(1),
            );
        }
        outcome
    }
}

impl ProcessSpawnProvider for NativeProcessSpawn {
    fn name(&self) -> &str {
        "native-process-spawn"
    }

    fn preflight_request(&self, request: &ProcessSpawnRequest) -> Result<(), ProcessSpawnError> {
        self.preflight_process_request(request)
    }

    fn prepare_request(
        &self,
        request: &ProcessSpawnRequest,
    ) -> Result<ProcessSpawnRequest, ProcessSpawnError> {
        self.prepare_process_request(request)
    }

    fn perform(
        &self,
        request: &ProcessSpawnRequest,
        granted: &[ProcessSpawnCapability],
    ) -> ProcessSpawnOutcome {
        self.perform_controlled(request, granted, Arc::new(UnrestrictedProcessSpawnControl))
    }

    fn perform_controlled(
        &self,
        request: &ProcessSpawnRequest,
        granted: &[ProcessSpawnCapability],
        control: Arc<dyn ProcessSpawnControl>,
    ) -> ProcessSpawnOutcome {
        let required = request.required_capability();
        if !process_capability_granted(granted, required) {
            return Err(ProcessSpawnError::CapabilityMissing {
                capability: required,
            });
        }
        self.preflight_process_request(request)?;
        control.checkpoint()?;
        let request = self.prepare_process_request(request)?;
        control.checkpoint()?;
        match &request {
            ProcessSpawnRequest::Run {
                launch,
                stdin,
                timeout_millis,
            } => self.run_controlled(launch, stdin, *timeout_millis, control.as_ref()),
            ProcessSpawnRequest::Spawn { launch } => {
                self.spawn_controlled(launch, Arc::clone(&control))
            }
            ProcessSpawnRequest::WriteStdin { handle, data } => {
                control.checkpoint()?;
                self.write_stdin(handle, data)
            }
            ProcessSpawnRequest::CloseStdin { handle } => {
                control.checkpoint()?;
                self.close_stdin(handle)
            }
            ProcessSpawnRequest::Wait {
                handle,
                timeout_millis,
            } => self.wait_controlled(handle, *timeout_millis, control.as_ref()),
            ProcessSpawnRequest::Kill { handle, signal } => {
                control.checkpoint()?;
                self.kill_controlled(handle, *signal, control.as_ref())
            }
            ProcessSpawnRequest::Cleanup { .. } => Err(ProcessSpawnError::Denied {
                reason: "process cleanup is an engine-owned teardown operation".to_string(),
            }),
        }
    }

    fn cleanup_handle(&self, handle: &str) -> ProcessSpawnOutcome {
        let state = lock_unpoison(&self.children).remove(handle);
        cleanup_lifecycle_child(state)
    }
}

impl Drop for NativeProcessSpawn {
    fn drop(&mut self) {
        let children = {
            let mut children = lock_unpoison(&self.children);
            std::mem::take(&mut *children)
        };
        for (_, state) in children {
            let _ = cleanup_lifecycle_child(Some(state));
        }
    }
}

struct ValidatedLaunch {
    executable: PathBuf,
    executable_file: Option<File>,
    argv: Vec<String>,
    env: BTreeMap<String, String>,
    cwd: PathBuf,
    stdio: ProcessStdio,
}

impl fmt::Debug for ValidatedLaunch {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let argv_bytes = self.argv.iter().fold(0usize, |total, argument| {
            total.saturating_add(argument.len())
        });
        let env_value_bytes = self
            .env
            .values()
            .fold(0usize, |total, value| total.saturating_add(value.len()));

        f.debug_struct("ValidatedLaunch")
            .field("executable_bytes", &self.executable.as_os_str().len())
            .field("argv_count", &self.argv.len())
            .field("argv_bytes", &argv_bytes)
            .field("env_count", &self.env.len())
            .field("env_value_bytes", &env_value_bytes)
            .field("cwd_bytes", &self.cwd.as_os_str().len())
            .field("stdio", &self.stdio)
            .finish()
    }
}

fn validate_policy(policy: &ProcessSpawnPolicy) -> Result<(), ProcessSpawnError> {
    let root = canonical_directory(
        Path::new(&policy.jailed_cwd_root),
        "canonicalize jailed cwd root",
    )?;
    if path_string(&root)? != policy.jailed_cwd_root {
        return Err(policy_error(
            "noncanonical_cwd_root",
            "jailed cwd root must be its exact canonical path",
        ));
    }
    enforce_limit(
        "fixed_env_count",
        u64::try_from(policy.fixed_env.len()).unwrap_or(u64::MAX),
        policy.limits.max_env_count,
    )?;
    let mut fixed_env_bytes = 0_u64;
    for (key, value) in &policy.fixed_env {
        validate_env_pair(key, value)?;
        fixed_env_bytes = fixed_env_bytes
            .saturating_add(u64::try_from(key.len()).unwrap_or(u64::MAX))
            .saturating_add(u64::try_from(value.len()).unwrap_or(u64::MAX));
    }
    enforce_limit(
        "fixed_env_bytes",
        fixed_env_bytes,
        policy.limits.max_env_bytes,
    )?;
    for executable in policy.allowed_executables.keys() {
        enforce_limit(
            "executable_path_bytes",
            u64::try_from(executable.len()).unwrap_or(u64::MAX),
            policy.limits.max_executable_path_bytes,
        )?;
        let path = Path::new(executable);
        if !path.is_absolute() {
            return Err(policy_error(
                "noncanonical_policy_executable",
                format!("allowlisted executable is not absolute: {executable}"),
            ));
        }
        let canonical = std::fs::canonicalize(path).map_err(|error| ProcessSpawnError::Io {
            operation: "validate allowlisted executable".to_string(),
            detail: error.to_string(),
        })?;
        if path_string(&canonical)? != *executable || !canonical.is_file() {
            return Err(policy_error(
                "noncanonical_policy_executable",
                format!("allowlisted executable is not an exact canonical file: {executable}"),
            ));
        }
        let executable_bytes = canonical
            .metadata()
            .map_err(|error| ProcessSpawnError::Io {
                operation: "inspect allowlisted executable".to_string(),
                detail: error.to_string(),
            })?
            .len();
        enforce_limit(
            "executable_bytes",
            executable_bytes,
            policy.limits.max_executable_bytes,
        )?;
    }
    for (alias, executable) in &policy.executable_aliases {
        validate_executable_alias(alias)?;
        if !policy.allowed_executables.contains_key(executable) {
            return Err(policy_error(
                "alias_target_denied",
                format!("alias {alias} target is not an allowlisted executable"),
            ));
        }
    }
    match (policy.allow_shell, policy.shell_executable_alias.as_deref()) {
        (true, Some(alias)) => {
            validate_executable_alias(alias)?;
            if !policy.executable_aliases.contains_key(alias) {
                return Err(policy_error(
                    "shell_alias_denied",
                    format!("shell alias {alias} is not in executable_aliases"),
                ));
            }
        }
        (true, None) => {
            return Err(policy_error(
                "shell_not_configured",
                "allow_shell requires shell_executable_alias",
            ));
        }
        (false, Some(_)) => {
            return Err(policy_error(
                "shell_disabled_but_configured",
                "shell_executable_alias requires allow_shell=true",
            ));
        }
        (false, None) => {}
    }
    if policy.limits.max_children == 0 {
        return Err(policy_error(
            "invalid_limit",
            "max_children must be greater than zero",
        ));
    }
    if policy.limits.max_runtime_millis == 0 {
        return Err(policy_error(
            "invalid_limit",
            "max_runtime_millis must be greater than zero",
        ));
    }
    if policy.limits.max_executable_path_bytes == 0
        || policy.limits.max_executable_bytes == 0
        || policy.limits.max_cwd_bytes == 0
        || policy.limits.max_prelaunch_bytes == 0
        || policy.limits.max_request_bytes == 0
    {
        return Err(policy_error(
            "invalid_limit",
            "executable, cwd, prelaunch, and request byte limits must be greater than zero",
        ));
    }
    Ok(())
}

fn validate_env_pair(key: &str, value: &str) -> Result<(), ProcessSpawnError> {
    if key.is_empty() || key.contains('=') || key.contains('\0') || value.contains('\0') {
        return Err(policy_error(
            "invalid_env",
            format!("invalid environment key/value for {key:?}"),
        ));
    }
    if matches!(
        key,
        "LD_PRELOAD"
            | "LD_LIBRARY_PATH"
            | "DYLD_INSERT_LIBRARIES"
            | "DYLD_LIBRARY_PATH"
            | "BASH_ENV"
            | "ENV"
            | "SHELLOPTS"
    ) {
        return Err(policy_error(
            "dangerous_env",
            format!("environment key {key} can alter executable loading or shell startup"),
        ));
    }
    Ok(())
}

fn validate_executable_alias(alias: &str) -> Result<(), ProcessSpawnError> {
    if alias.is_empty()
        || alias == "."
        || alias == ".."
        || alias.contains('\0')
        || alias.contains('/')
        || alias.contains('\\')
        || !alias
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-'))
    {
        return Err(policy_error(
            "invalid_executable_alias",
            format!("invalid bare executable alias {alias:?}"),
        ));
    }
    Ok(())
}

fn canonical_directory(path: &Path, operation: &str) -> Result<PathBuf, ProcessSpawnError> {
    let canonical = std::fs::canonicalize(path).map_err(|error| ProcessSpawnError::Io {
        operation: operation.to_string(),
        detail: error.to_string(),
    })?;
    if !canonical.is_dir() {
        return Err(policy_error(
            "cwd_not_directory",
            canonical.display().to_string(),
        ));
    }
    Ok(canonical)
}

fn path_string(path: &Path) -> Result<String, ProcessSpawnError> {
    path.to_str()
        .map(str::to_owned)
        .ok_or_else(|| policy_error("non_utf8_path", path.display().to_string()))
}

fn digest_file(path: &Path, maximum_bytes: u64) -> Result<[u8; 32], ProcessSpawnError> {
    let mut file = File::open(path).map_err(|error| ProcessSpawnError::Io {
        operation: "open executable for digest".to_string(),
        detail: error.to_string(),
    })?;
    let executable_bytes = file
        .metadata()
        .map_err(|error| ProcessSpawnError::Io {
            operation: "inspect executable for digest".to_string(),
            detail: error.to_string(),
        })?
        .len();
    enforce_limit("executable_bytes", executable_bytes, maximum_bytes)?;
    let mut digest = Sha256::new();
    let mut buffer = [0_u8; 16 * 1024];
    let mut total_bytes = 0_u64;
    loop {
        let read = file
            .read(&mut buffer)
            .map_err(|error| ProcessSpawnError::Io {
                operation: "read executable for digest".to_string(),
                detail: error.to_string(),
            })?;
        if read == 0 {
            break;
        }
        total_bytes = total_bytes.saturating_add(u64::try_from(read).unwrap_or(u64::MAX));
        enforce_limit("executable_bytes", total_bytes, maximum_bytes)?;
        digest.update(&buffer[..read]);
    }
    Ok(digest.finalize().into())
}

#[cfg(any(target_os = "linux", target_os = "freebsd"))]
fn open_verified_executable(
    executable: &Path,
    expected_digest: &[u8; 32],
    executable_string: &str,
    maximum_bytes: u64,
    control: &dyn ProcessSpawnControl,
) -> Result<File, ProcessSpawnError> {
    control.checkpoint()?;
    let mut executable_file = File::open(executable).map_err(|error| ProcessSpawnError::Io {
        operation: "open executable identity".to_string(),
        detail: error.to_string(),
    })?;
    let metadata = executable_file
        .metadata()
        .map_err(|error| ProcessSpawnError::Io {
            operation: "inspect executable identity".to_string(),
            detail: error.to_string(),
        })?;
    if !metadata.is_file() {
        return Err(policy_error(
            "executable_not_file",
            executable_string.to_string(),
        ));
    }
    enforce_limit("executable_bytes", metadata.len(), maximum_bytes)?;

    let mut digest = Sha256::new();
    let mut buffer = [0_u8; 16 * 1024];
    let mut total_bytes = 0_u64;
    loop {
        control.checkpoint()?;
        let read = executable_file
            .read(&mut buffer)
            .map_err(|error| ProcessSpawnError::Io {
                operation: "read executable identity".to_string(),
                detail: error.to_string(),
            })?;
        if read == 0 {
            break;
        }
        total_bytes = total_bytes.saturating_add(u64::try_from(read).unwrap_or(u64::MAX));
        enforce_limit("executable_bytes", total_bytes, maximum_bytes)?;
        digest.update(&buffer[..read]);
    }
    let actual_digest: [u8; 32] = digest.finalize().into();
    if &actual_digest != expected_digest {
        return Err(policy_error(
            "executable_digest_mismatch",
            format!("digest changed for {executable_string}"),
        ));
    }
    Ok(executable_file)
}

#[cfg(not(any(target_os = "linux", target_os = "freebsd")))]
fn open_verified_executable(
    _executable: &Path,
    _expected_digest: &[u8; 32],
    _executable_string: &str,
    _maximum_bytes: u64,
    _control: &dyn ProcessSpawnControl,
) -> Result<File, ProcessSpawnError> {
    Err(ProcessSpawnError::NotImplemented {
        what: "descriptor-pinned executable launch is unavailable on this platform".to_string(),
    })
}

#[cfg(target_os = "linux")]
fn pinned_executable_path(image: &File) -> Result<PathBuf, ProcessSpawnError> {
    Ok(PathBuf::from(format!(
        "/proc/self/fd/{}",
        image.as_raw_fd()
    )))
}

#[cfg(target_os = "freebsd")]
fn pinned_executable_path(image: &File) -> Result<PathBuf, ProcessSpawnError> {
    Ok(PathBuf::from(format!("/dev/fd/{}", image.as_raw_fd())))
}

#[cfg(not(any(target_os = "linux", target_os = "freebsd")))]
fn pinned_executable_path(_image: &File) -> Result<PathBuf, ProcessSpawnError> {
    Err(ProcessSpawnError::NotImplemented {
        what: "descriptor-pinned executable launch is unavailable on this platform".to_string(),
    })
}

fn policy_error(code: impl Into<String>, detail: impl Into<String>) -> ProcessSpawnError {
    ProcessSpawnError::PolicyViolation {
        code: code.into(),
        detail: detail.into(),
    }
}

fn unknown_handle(handle: &str) -> ProcessSpawnError {
    ProcessSpawnError::UnknownHandle {
        handle: handle.to_string(),
    }
}

fn lock_unpoison<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    match mutex.lock() {
        Ok(guard) => guard,
        Err(poisoned) => poisoned.into_inner(),
    }
}

fn enforce_limit(limit: &str, actual: u64, maximum: u64) -> Result<(), ProcessSpawnError> {
    if actual > maximum {
        return Err(ProcessSpawnError::LimitExceeded {
            limit: limit.to_string(),
            actual,
            maximum,
        });
    }
    Ok(())
}

#[derive(Debug, Default)]
struct CountingWriter {
    bytes: u64,
}

impl Write for CountingWriter {
    fn write(&mut self, buffer: &[u8]) -> std::io::Result<usize> {
        self.bytes = self
            .bytes
            .saturating_add(u64::try_from(buffer.len()).unwrap_or(u64::MAX));
        Ok(buffer.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

fn to_stdio(mode: ProcessStdioMode) -> Stdio {
    match mode {
        ProcessStdioMode::Pipe => Stdio::piped(),
        ProcessStdioMode::Null => Stdio::null(),
    }
}

#[cfg(unix)]
fn spawn_reader<R>(
    reader: R,
    maximum: u64,
    stream: &'static str,
) -> Result<OutputDrain, ProcessSpawnError>
where
    R: AsFd + Read + Send + 'static,
{
    let flags = rustix::fs::fcntl_getfl(reader.as_fd()).map_err(|error| ProcessSpawnError::Io {
        operation: format!("read {stream} flags"),
        detail: error.to_string(),
    })?;
    rustix::fs::fcntl_setfl(reader.as_fd(), flags | rustix::fs::OFlags::NONBLOCK).map_err(
        |error| ProcessSpawnError::Io {
            operation: format!("set {stream} nonblocking"),
            detail: error.to_string(),
        },
    )?;
    let cancel = Arc::new(AtomicBool::new(false));
    let reader_cancel = Arc::clone(&cancel);
    let thread = thread::Builder::new()
        .name(format!("franken-process-{stream}"))
        .spawn(move || read_bounded(reader, maximum, &reader_cancel))
        .map_err(|error| ProcessSpawnError::Io {
            operation: format!("start {stream} drain"),
            detail: error.to_string(),
        })?;
    Ok(OutputDrain { cancel, thread })
}

#[cfg(not(unix))]
fn spawn_reader<R>(
    _reader: R,
    _maximum: u64,
    _stream: &'static str,
) -> Result<OutputDrain, ProcessSpawnError>
where
    R: Read + Send + 'static,
{
    Err(ProcessSpawnError::NotImplemented {
        what: "bounded native output drains require a platform containment backend".to_string(),
    })
}

fn spawn_stdin_writer(
    mut stdin: ChildStdin,
    data: Vec<u8>,
) -> Result<JoinHandle<std::io::Result<()>>, ProcessSpawnError> {
    thread::Builder::new()
        .name("franken-process-stdin".to_string())
        .spawn(move || stdin.write_all(&data))
        .map_err(|error| ProcessSpawnError::Io {
            operation: "start stdin writer".to_string(),
            detail: error.to_string(),
        })
}

fn join_stdin_writer(
    writer: Option<JoinHandle<std::io::Result<()>>>,
) -> Result<(), ProcessSpawnError> {
    let Some(writer) = writer else {
        return Ok(());
    };
    writer
        .join()
        .map_err(|_| ProcessSpawnError::Io {
            operation: "join stdin writer".to_string(),
            detail: "stdin writer thread panicked".to_string(),
        })?
        .map_err(|error| ProcessSpawnError::Io {
            operation: "write stdin".to_string(),
            detail: error.to_string(),
        })
}

/// Start the dedicated stdin writer thread for a lifecycle spawn (bd-m42c2).
/// The thread takes ownership of the pipe: queued writes drain off the
/// interpreter, and `Close` (or sender drop) closes the pipe to deliver EOF.
/// On thread-spawn failure the returned handle carries no sender, so the
/// pipe closes immediately instead of leaving an unwritable fd open.
fn spawn_lifecycle_stdin_writer(stdin: ChildStdin) -> StdinWriter {
    let (tx, rx) = channel::<StdinWriterCommand>();
    let spawned = thread::Builder::new()
        .name("franken-process-stdin".to_string())
        .spawn(move || {
            let mut stdin = stdin;
            // `rx` iteration ends on Close or sender drop; dropping `stdin`
            // afterwards is what delivers EOF to the child.
            for command in rx {
                match command {
                    StdinWriterCommand::Write(data) => {
                        if stdin.write_all(&data).is_err() {
                            // Pipe closed (child exited or containment kill):
                            // stop consuming. Later sends fail at the write()
                            // boundary as typed Io errors.
                            break;
                        }
                    }
                    StdinWriterCommand::Close => break,
                }
            }
        });
    if spawned.is_err() {
        return StdinWriter { tx: None };
    }
    StdinWriter { tx: Some(tx) }
}

fn read_bounded(
    mut reader: impl Read,
    maximum: u64,
    cancel: &AtomicBool,
) -> std::io::Result<CapturedOutput> {
    let capacity = usize::try_from(maximum.min(64 * 1024)).unwrap_or(64 * 1024);
    let mut bytes = Vec::with_capacity(capacity);
    let mut overflowed = false;
    let mut chunk = [0_u8; 8192];
    loop {
        if cancel.load(Ordering::Acquire) {
            break;
        }
        let read = match reader.read(&mut chunk) {
            Ok(read) => read,
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                thread::sleep(Duration::from_millis(2));
                continue;
            }
            Err(error) => return Err(error),
        };
        if read == 0 {
            break;
        }
        let remaining = maximum.saturating_sub(u64::try_from(bytes.len()).unwrap_or(u64::MAX));
        let retain = usize::try_from(remaining).unwrap_or(usize::MAX).min(read);
        bytes.extend_from_slice(&chunk[..retain]);
        if retain < read {
            overflowed = true;
        }
    }
    Ok(CapturedOutput {
        bytes,
        overflowed,
        maximum,
    })
}

fn cancel_watchdog(running: &mut RunningChild) {
    if let Some(cancel) = running.watchdog_cancel.take() {
        let _ = cancel.send(());
    }
}

fn trim_terminal_children(children: &mut ChildMap, maximum: usize) {
    while children
        .values()
        .filter(|child| matches!(child, LifecycleChild::Terminal(_)))
        .count()
        > maximum
    {
        let Some(oldest) = children.iter().find_map(|(handle, child)| {
            matches!(child, LifecycleChild::Terminal(_)).then(|| handle.clone())
        }) else {
            break;
        };
        children.remove(&oldest);
    }
}

fn terminal_operation_error(handle: &str, outcome: &ProcessSpawnOutcome) -> ProcessSpawnOutcome {
    match outcome {
        Err(error) => Err(error.clone()),
        Ok(_) => Err(ProcessSpawnError::InvalidState {
            detail: format!("process handle {handle} has already completed"),
        }),
    }
}

fn collect_outputs(mut running: RunningChild) -> Result<(Vec<u8>, Vec<u8>), ProcessSpawnError> {
    collect_outputs_inner(&mut running, None)
}

fn collect_outputs_controlled(
    mut running: RunningChild,
    control: &dyn ProcessSpawnControl,
) -> Result<(Vec<u8>, Vec<u8>), ProcessSpawnError> {
    collect_outputs_inner(&mut running, Some(control))
}

/// Best-effort bounded capture for failure lanes (bd-k709s): keeps whatever
/// prefix bytes the drain threads produced before containment teardown
/// finished. Bytes were already capped by the policy per-stream limit inside
/// [`read_bounded`], so no additional truncation is required. Never fails and
/// never reports overflow state: the caller returns the primary typed
/// failure separately.
fn collect_outputs_lossy(mut running: RunningChild) -> (Vec<u8>, Vec<u8>) {
    cancel_watchdog(&mut running);
    let _ = terminate_remaining_process_group(&running);
    let _ = wait_for_output_drains_controlled(&running, Duration::from_millis(250), None);
    (
        join_reader_lossy(running.stdout.take()),
        join_reader_lossy(running.stderr.take()),
    )
}

/// Lossy counterpart of [`join_reader`]: on drain-thread panic, drain I/O
/// failure, or post-teardown containment violation the captured prefix is
/// still preferred over an empty buffer, and no secondary error is raised.
fn join_reader_lossy(reader: Option<OutputDrain>) -> Vec<u8> {
    let Some(reader) = reader else {
        return Vec::new();
    };
    let forced_cancel = !reader.thread.is_finished();
    if forced_cancel {
        reader.cancel.store(true, Ordering::Release);
    }
    match reader.thread.join() {
        Ok(Ok(captured)) => captured.bytes,
        Ok(Err(_)) | Err(_) => Vec::new(),
    }
}

fn collect_outputs_inner(
    running: &mut RunningChild,
    control: Option<&dyn ProcessSpawnControl>,
) -> Result<(Vec<u8>, Vec<u8>), ProcessSpawnError> {
    cancel_watchdog(running);
    // The direct child owns a private process group. Once it has been reaped,
    // always terminate that group before accepting success: a descendant can
    // redirect both capture pipes and would otherwise be invisible to drain
    // completion. ESRCH is success when the group is already empty.
    let group_teardown = terminate_remaining_process_group(running);
    let control_error =
        wait_for_output_drains_controlled(running, Duration::from_millis(250), control).err();
    let stdout = join_reader(running.stdout.take(), "stdout");
    let stderr = join_reader(running.stderr.take(), "stderr");
    // A temporal refusal observed during output drain is the primary guest
    // outcome. Group termination and reader joins above still run to preserve
    // containment before the denial is returned.
    if let Some(error) = control_error {
        return Err(error);
    }
    group_teardown?;
    let stdout = stdout?;
    let stderr = stderr?;
    if stdout.overflowed || stderr.overflowed {
        let failure = if stdout.overflowed {
            ProcessSpawnError::LimitExceeded {
                limit: "stdout_bytes".to_string(),
                actual: stdout.maximum.saturating_add(1),
                maximum: stdout.maximum,
            }
        } else {
            ProcessSpawnError::LimitExceeded {
                limit: "stderr_bytes".to_string(),
                actual: stderr.maximum.saturating_add(1),
                maximum: stderr.maximum,
            }
        };
        // bd-k709s: the captured prefixes are already bounded by the policy
        // per-stream cap, so they are retained on the failure outcome instead
        // of being discarded with the drained pipes.
        return Err(ProcessSpawnError::PartialOutputFailed {
            failure: Box::new(failure),
            signal: None,
            partial_stdout: stdout.bytes,
            partial_stderr: stderr.bytes,
        });
    }
    Ok((stdout.bytes, stderr.bytes))
}

fn join_reader(
    reader: Option<OutputDrain>,
    stream: &str,
) -> Result<CapturedOutput, ProcessSpawnError> {
    let Some(reader) = reader else {
        return Ok(CapturedOutput {
            bytes: Vec::new(),
            overflowed: false,
            maximum: 0,
        });
    };
    let forced_cancel = !reader.thread.is_finished();
    if forced_cancel {
        reader.cancel.store(true, Ordering::Release);
    }
    let captured = reader
        .thread
        .join()
        .map_err(|_| ProcessSpawnError::Io {
            operation: format!("join {stream} drain"),
            detail: "drain thread panicked".to_string(),
        })?
        .map_err(|error| ProcessSpawnError::Io {
            operation: format!("drain {stream}"),
            detail: error.to_string(),
        })?;
    if forced_cancel {
        return Err(ProcessSpawnError::PolicyViolation {
            code: "process_tree_escape".to_string(),
            detail: format!(
                "{stream} remained open after process-group teardown; a descendant escaped containment"
            ),
        });
    }
    Ok(captured)
}

fn output_drains_finished(running: &RunningChild) -> bool {
    running
        .stdout
        .as_ref()
        .is_none_or(|reader| reader.thread.is_finished())
        && running
            .stderr
            .as_ref()
            .is_none_or(|reader| reader.thread.is_finished())
}

fn wait_for_output_drains_controlled(
    running: &RunningChild,
    timeout: Duration,
    control: Option<&dyn ProcessSpawnControl>,
) -> Result<(), ProcessSpawnError> {
    let deadline = Instant::now().checked_add(timeout);
    while !output_drains_finished(running)
        && deadline.is_some_and(|deadline| Instant::now() < deadline)
    {
        if let Some(control) = control {
            control.checkpoint()?;
        }
        thread::sleep(Duration::from_millis(2));
    }
    if let Some(control) = control {
        control.checkpoint()?;
    }
    Ok(())
}

#[cfg(unix)]
fn terminate_remaining_process_group(running: &RunningChild) -> Result<(), ProcessSpawnError> {
    terminate_process_group_id(running.process_group)
}

#[cfg(unix)]
fn terminate_process_group_id(
    process_group: rustix::process::Pid,
) -> Result<(), ProcessSpawnError> {
    match rustix::process::kill_process_group(process_group, rustix::process::Signal::KILL) {
        Ok(()) | Err(rustix::io::Errno::SRCH) => Ok(()),
        Err(error) => Err(ProcessSpawnError::Io {
            operation: "terminate process group".to_string(),
            detail: error.to_string(),
        }),
    }
}

/// Deliver an arbitrary allowed signal to a private process group
/// (bd-m42c2). ESRCH is success: the group may already be gone.
#[cfg(unix)]
fn signal_process_group_id(
    process_group: rustix::process::Pid,
    signal: rustix::process::Signal,
) -> Result<(), ProcessSpawnError> {
    match rustix::process::kill_process_group(process_group, signal) {
        Ok(()) | Err(rustix::io::Errno::SRCH) => Ok(()),
        Err(error) => Err(ProcessSpawnError::Io {
            operation: "signal process group".to_string(),
            detail: error.to_string(),
        }),
    }
}

/// Map the provider's guest-visible signal vocabulary onto the platform.
#[cfg(unix)]
const fn rustix_signal(signal: ProcessSignal) -> rustix::process::Signal {
    match signal {
        ProcessSignal::Interrupt => rustix::process::Signal::INT,
        ProcessSignal::Terminate => rustix::process::Signal::TERM,
        ProcessSignal::Kill => rustix::process::Signal::KILL,
    }
}

#[cfg(not(unix))]
fn terminate_remaining_process_group(_running: &RunningChild) -> Result<(), ProcessSpawnError> {
    Err(ProcessSpawnError::NotImplemented {
        what: "native process-group teardown is unavailable on this platform".to_string(),
    })
}

fn effective_timeout(requested_millis: Option<u64>, policy_millis: u64) -> Duration {
    let requested_millis = match requested_millis {
        None | Some(0) => policy_millis,
        Some(requested_millis) => requested_millis.min(policy_millis),
    };
    Duration::from_millis(requested_millis)
}

#[cfg(test)]
fn wait_and_collect(
    running: RunningChild,
    timeout: Duration,
) -> Result<(ProcessExit, Vec<u8>, Vec<u8>), ProcessSpawnError> {
    wait_and_collect_controlled(running, timeout, &UnrestrictedProcessSpawnControl)
}

fn wait_and_collect_controlled(
    mut running: RunningChild,
    timeout: Duration,
    control: &dyn ProcessSpawnControl,
) -> Result<(ProcessExit, Vec<u8>, Vec<u8>), ProcessSpawnError> {
    let deadline = Instant::now().checked_add(timeout);
    let status = loop {
        match running.child.try_wait() {
            Err(error) => {
                let _ = terminate_remaining_process_group(&running);
                kill_and_reap(&mut running.child);
                let (partial_stdout, partial_stderr) = collect_outputs_lossy(running);
                return Err(ProcessSpawnError::PartialOutputFailed {
                    failure: Box::new(ProcessSpawnError::Io {
                        operation: "poll child".to_string(),
                        detail: error.to_string(),
                    }),
                    signal: None,
                    partial_stdout,
                    partial_stderr,
                });
            }
            Ok(Some(status)) => break status,
            Ok(None) => {}
        }
        if let Err(error) = control.checkpoint() {
            let _ = terminate_remaining_process_group(&running);
            kill_and_reap(&mut running.child);
            let _ = collect_outputs(running);
            return Err(error);
        }
        if deadline.is_none_or(|deadline| Instant::now() >= deadline) {
            let _ = terminate_remaining_process_group(&running);
            let signal = kill_and_reap_capture(&mut running.child);
            let elapsed = elapsed_millis(running.started);
            let (partial_stdout, partial_stderr) = collect_outputs_lossy(running);
            return Err(ProcessSpawnError::PartialOutputFailed {
                failure: Box::new(ProcessSpawnError::TimedOut {
                    runtime_millis: elapsed,
                }),
                signal,
                partial_stdout,
                partial_stderr,
            });
        }
        thread::sleep(Duration::from_millis(2));
    };
    let exit = exit_from_status(status);
    let (stdout, stderr) = collect_outputs_controlled(running, control)?;
    Ok((exit, stdout, stderr))
}

fn cleanup_lifecycle_child(state: Option<LifecycleChild>) -> ProcessSpawnOutcome {
    let Some(state) = state else {
        return Ok(ProcessSpawnResponse::Cleaned { was_present: false });
    };
    let LifecycleChild::Running(mut running) = state else {
        return Ok(ProcessSpawnResponse::Cleaned { was_present: true });
    };
    cancel_watchdog(&mut running);
    let terminate = terminate_remaining_process_group(&running);
    let reap = kill_and_reap_fallible(&mut running.child);
    let outputs = collect_outputs(running);
    terminate?;
    reap?;
    outputs?;
    Ok(ProcessSpawnResponse::Cleaned { was_present: true })
}

fn kill_and_reap_fallible(child: &mut Child) -> Result<(), ProcessSpawnError> {
    let poll_error = match child.try_wait() {
        Ok(Some(_)) => return Ok(()),
        Ok(None) => None,
        Err(error) => Some(error),
    };
    let kill_error = child.kill().err();
    let wait_error = child.wait().err();
    if let Some(error) = poll_error.or(kill_error).or(wait_error) {
        return Err(ProcessSpawnError::Io {
            operation: "kill and reap child".to_string(),
            detail: error.to_string(),
        });
    }
    Ok(())
}

fn kill_and_reap(child: &mut Child) {
    let _ = kill_and_reap_fallible(child);
}

/// Kill and reap the child, returning the observed terminating signal when
/// the platform exposes one (bd-k709s). Best-effort like [`kill_and_reap`]:
/// containment must never depend on the capture.
fn kill_and_reap_capture(child: &mut Child) -> Option<i32> {
    let status = if let Ok(Some(status)) = child.try_wait() {
        status
    } else {
        let _ = child.kill();
        child.wait().ok()?
    };
    exit_from_status(status).signal
}

fn elapsed_millis(started: Instant) -> u64 {
    u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX)
}

fn exit_from_status(status: ExitStatus) -> ProcessExit {
    #[cfg(unix)]
    let signal = {
        use std::os::unix::process::ExitStatusExt;
        status.signal()
    };
    #[cfg(not(unix))]
    let signal = None;
    ProcessExit {
        success: status.success(),
        code: status.code(),
        signal,
    }
}

fn fresh_scope() -> String {
    static SCOPE_SEQUENCE: AtomicU64 = AtomicU64::new(0);
    let sequence = SCOPE_SEQUENCE.fetch_add(1, Ordering::Relaxed);
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos();
    let mut digest = Sha256::new();
    digest.update(std::process::id().to_le_bytes());
    digest.update(sequence.to_le_bytes());
    digest.update(now.to_le_bytes());
    let digest: [u8; 32] = digest.finalize().into();
    let mut scope = String::with_capacity(24);
    for byte in &digest[..12] {
        scope.push(hex_digit(byte >> 4));
        scope.push(hex_digit(byte & 0x0f));
    }
    scope
}

fn hex_digit(value: u8) -> char {
    match value {
        0..=9 => char::from(b'0' + value),
        10..=15 => char::from(b'a' + value - 10),
        _ => unreachable!("four-bit hex digit"),
    }
}

/// Recorder mode for deterministic process replay.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProcessSpawnReplayMode {
    Record,
    Replay,
}

/// Process transcript lifecycle used by the execution orchestrator.
pub trait ProcessSpawnRecorder: fmt::Debug + Send + Sync {
    fn begin_execution(&self) -> Result<(), ProcessSpawnError>;
    fn replay(&self, request: &ProcessSpawnRequest) -> Option<ProcessSpawnOutcome>;
    fn record(&self, request: &ProcessSpawnRequest, outcome: &ProcessSpawnOutcome);
    fn finish_execution(
        &self,
    ) -> Result<Vec<(ProcessSpawnRequest, ProcessSpawnOutcome)>, ProcessSpawnError>;
    fn recorded_entries(&self) -> Vec<(ProcessSpawnRequest, ProcessSpawnOutcome)> {
        Vec::new()
    }
}

/// Replay through the legacy family-local transcript.
///
/// A missing replay match fails closed because this recorder cannot reserve a
/// position in the globally ordered host-effect journal before provider work.
pub fn perform_recorded(
    _provider: &dyn ProcessSpawnProvider,
    recorder: Option<&dyn ProcessSpawnRecorder>,
    request: &ProcessSpawnRequest,
    granted: &[ProcessSpawnCapability],
) -> ProcessSpawnOutcome {
    let required = request.required_capability();
    if !process_capability_granted(granted, required) {
        let outcome = Err(ProcessSpawnError::CapabilityMissing {
            capability: required,
        });
        if let Some(recorder) = recorder {
            recorder.record(request, &outcome);
        }
        return outcome;
    }
    if let Some(outcome) = recorder.and_then(|recorder| recorder.replay(request)) {
        return outcome;
    }

    // The legacy family-local transcript cannot prove a global reservation
    // across process and ordinary host effects. It therefore remains replay
    // only: live execution must use `InMemoryHostEffectJournal`, whose opaque
    // reservation is accepted before provider preparation or dispatch.
    let outcome = Err(ProcessSpawnError::Denied {
        reason:
            "live process execution requires a globally ordered host-effect journal reservation"
                .to_string(),
    });
    if let Some(recorder) = recorder {
        recorder.record(request, &outcome);
    }
    outcome
}

/// In-memory exact-match transcript reference implementation.
#[derive(Debug)]
pub struct InMemoryProcessSpawnTranscript {
    mode: ProcessSpawnReplayMode,
    entries: Mutex<Vec<(ProcessSpawnRequest, ProcessSpawnOutcome)>>,
    state: Mutex<ProcessTranscriptState>,
}

#[derive(Debug, Default)]
enum ProcessTranscriptState {
    #[default]
    Idle,
    Recording {
        start: usize,
    },
    Replaying {
        cursor: usize,
    },
    Finalized,
    Poisoned(ProcessSpawnError),
}

impl InMemoryProcessSpawnTranscript {
    #[must_use]
    pub fn recording() -> Self {
        Self {
            mode: ProcessSpawnReplayMode::Record,
            entries: Mutex::new(Vec::new()),
            state: Mutex::new(ProcessTranscriptState::Idle),
        }
    }

    #[must_use]
    pub fn replaying(entries: Vec<(ProcessSpawnRequest, ProcessSpawnOutcome)>) -> Self {
        Self {
            mode: ProcessSpawnReplayMode::Replay,
            entries: Mutex::new(entries),
            state: Mutex::new(ProcessTranscriptState::Idle),
        }
    }

    #[must_use]
    pub const fn mode(&self) -> ProcessSpawnReplayMode {
        self.mode
    }

    #[must_use]
    pub fn entries(&self) -> Vec<(ProcessSpawnRequest, ProcessSpawnOutcome)> {
        lock_unpoison(&self.entries).clone()
    }
}

impl ProcessSpawnRecorder for InMemoryProcessSpawnTranscript {
    fn begin_execution(&self) -> Result<(), ProcessSpawnError> {
        let mut state = lock_unpoison(&self.state);
        match &*state {
            ProcessTranscriptState::Idle => {
                *state = match self.mode {
                    ProcessSpawnReplayMode::Record => ProcessTranscriptState::Recording {
                        start: lock_unpoison(&self.entries).len(),
                    },
                    ProcessSpawnReplayMode::Replay => {
                        ProcessTranscriptState::Replaying { cursor: 0 }
                    }
                };
                Ok(())
            }
            ProcessTranscriptState::Recording { .. } | ProcessTranscriptState::Replaying { .. } => {
                Err(ProcessSpawnError::Denied {
                    reason: "process transcript execution already active".to_string(),
                })
            }
            ProcessTranscriptState::Finalized => Err(ProcessSpawnError::Denied {
                reason: "process replay transcript already finalized".to_string(),
            }),
            ProcessTranscriptState::Poisoned(error) => Err(error.clone()),
        }
    }

    fn replay(&self, request: &ProcessSpawnRequest) -> Option<ProcessSpawnOutcome> {
        if self.mode != ProcessSpawnReplayMode::Replay {
            return None;
        }
        let mut state = lock_unpoison(&self.state);
        let cursor = match &*state {
            ProcessTranscriptState::Replaying { cursor } => *cursor,
            ProcessTranscriptState::Poisoned(error) => return Some(Err(error.clone())),
            ProcessTranscriptState::Idle => {
                let error = ProcessSpawnError::Denied {
                    reason: "process replay attempted before begin_execution".to_string(),
                };
                *state = ProcessTranscriptState::Poisoned(error.clone());
                return Some(Err(error));
            }
            ProcessTranscriptState::Finalized => {
                return Some(Err(ProcessSpawnError::Denied {
                    reason: "process replay transcript already finalized".to_string(),
                }));
            }
            ProcessTranscriptState::Recording { .. } => {
                let error = ProcessSpawnError::Denied {
                    reason: "process replay state is inconsistent with recorder mode".to_string(),
                };
                *state = ProcessTranscriptState::Poisoned(error.clone());
                return Some(Err(error));
            }
        };
        let entries = lock_unpoison(&self.entries);
        match entries.get(cursor) {
            Some((recorded, outcome)) if recorded == request => {
                *state = ProcessTranscriptState::Replaying { cursor: cursor + 1 };
                Some(outcome.clone())
            }
            Some((recorded, _)) => {
                let error = ProcessSpawnError::ReplayDivergence {
                    index: cursor,
                    live_kind: request.kind().to_string(),
                    recorded_kind: recorded.kind().to_string(),
                    live_request_digest: process_spawn_request_digest(request),
                    recorded_request_digest: Some(process_spawn_request_digest(recorded)),
                };
                *state = ProcessTranscriptState::Poisoned(error.clone());
                Some(Err(error))
            }
            None => {
                let error = ProcessSpawnError::Denied {
                    reason: format!("process replay transcript exhausted at index {cursor}"),
                };
                *state = ProcessTranscriptState::Poisoned(error.clone());
                Some(Err(error))
            }
        }
    }

    fn record(&self, request: &ProcessSpawnRequest, outcome: &ProcessSpawnOutcome) {
        if self.mode == ProcessSpawnReplayMode::Record {
            lock_unpoison(&self.entries).push((request.clone(), outcome.clone()));
        }
    }

    fn finish_execution(
        &self,
    ) -> Result<Vec<(ProcessSpawnRequest, ProcessSpawnOutcome)>, ProcessSpawnError> {
        let mut state = lock_unpoison(&self.state);
        let entries = lock_unpoison(&self.entries);
        match &*state {
            ProcessTranscriptState::Recording { start } => {
                let current = entries
                    .get(*start..)
                    .ok_or_else(|| ProcessSpawnError::Denied {
                        reason: "process recording boundary exceeds transcript length".to_string(),
                    })?;
                let current = current.to_vec();
                *state = ProcessTranscriptState::Idle;
                Ok(current)
            }
            ProcessTranscriptState::Replaying { cursor } if *cursor == entries.len() => {
                let current = entries.clone();
                *state = ProcessTranscriptState::Finalized;
                Ok(current)
            }
            ProcessTranscriptState::Replaying { cursor } => {
                let error = ProcessSpawnError::Denied {
                    reason: format!(
                        "process replay finished with {} unused transcript entries starting at index {}",
                        entries.len() - *cursor,
                        cursor
                    ),
                };
                *state = ProcessTranscriptState::Poisoned(error.clone());
                Err(error)
            }
            ProcessTranscriptState::Poisoned(error) => Err(error.clone()),
            ProcessTranscriptState::Finalized => Err(ProcessSpawnError::Denied {
                reason: "process replay transcript already finalized".to_string(),
            }),
            ProcessTranscriptState::Idle => Err(ProcessSpawnError::Denied {
                reason: "process transcript execution was not begun".to_string(),
            }),
        }
    }

    fn recorded_entries(&self) -> Vec<(ProcessSpawnRequest, ProcessSpawnOutcome)> {
        self.entries()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn run_request(executable: String, argv: Vec<&str>) -> ProcessSpawnRequest {
        ProcessSpawnRequest::Run {
            launch: ProcessLaunch {
                executable,
                argv: argv.into_iter().map(str::to_string).collect(),
                env: BTreeMap::new(),
                cwd: None,
                shell: false,
                stdio: ProcessStdio::default(),
            },
            stdin: Vec::new(),
            timeout_millis: Some(1_000),
        }
    }

    #[cfg(unix)]
    fn executable(candidates: &[&str]) -> PathBuf {
        candidates
            .iter()
            .map(PathBuf::from)
            .find(|path| path.is_file())
            .and_then(|path| std::fs::canonicalize(path).ok())
            .expect("test executable")
    }

    #[cfg(unix)]
    fn provider_for(executable: &Path) -> (NativeProcessSpawn, String) {
        let mut policy = ProcessSpawnPolicy::jailed("/").expect("rooted policy");
        let canonical = policy
            .authorize_executable(executable)
            .expect("authorize executable");
        // Keep ordinary lifecycle tests insulated from scheduler stalls when
        // the full module runs in parallel. Timeout-specific tests supply a
        // much smaller per-request bound explicitly.
        policy.limits.max_runtime_millis = 10_000;
        (
            NativeProcessSpawn::new(policy).expect("native provider"),
            canonical,
        )
    }

    #[derive(Debug)]
    struct TestStopControl {
        stopped: Arc<AtomicUsize>,
    }

    impl ProcessSpawnControl for TestStopControl {
        fn checkpoint(&self) -> Result<(), ProcessSpawnError> {
            if self.stopped.load(Ordering::Acquire) == 0 {
                Ok(())
            } else {
                Err(ProcessSpawnError::Denied {
                    reason: "TEST_PROCESS_CONTROL_STOPPED".to_string(),
                })
            }
        }
    }

    #[test]
    fn native_preflight_enforces_each_shape_budget_at_the_exact_boundary() {
        let mut policy = ProcessSpawnPolicy::jailed("/").expect("rooted policy");
        policy.allowed_env_keys.insert("E".to_string());
        policy.limits.max_executable_path_bytes = 4;
        policy.limits.max_argv_count = 1;
        policy.limits.max_argv_bytes = 3;
        policy.limits.max_env_count = 1;
        policy.limits.max_env_bytes = 3;
        policy.limits.max_cwd_bytes = 3;
        policy.limits.max_prelaunch_bytes = 13;
        let boundary = ProcessSpawnRequest::Run {
            launch: ProcessLaunch {
                executable: "tool".to_string(),
                argv: vec!["arg".to_string()],
                env: BTreeMap::from([("E".to_string(), "vv".to_string())]),
                cwd: Some("cwd".to_string()),
                shell: false,
                stdio: ProcessStdio::default(),
            },
            stdin: Vec::new(),
            timeout_millis: None,
        };
        policy.limits.max_request_bytes = u64::try_from(
            serde_json::to_vec(&boundary)
                .expect("encode boundary")
                .len(),
        )
        .expect("request length fits u64");
        let provider = NativeProcessSpawn::new(policy).expect("native provider");
        provider
            .preflight_request(&boundary)
            .expect("every shape field is exactly at its configured boundary");

        let mut over_path = boundary.clone();
        let ProcessSpawnRequest::Run { launch, .. } = &mut over_path else {
            unreachable!("boundary request is Run")
        };
        launch.executable.push('x');
        assert!(matches!(
            provider.preflight_request(&over_path),
            Err(ProcessSpawnError::LimitExceeded { limit, .. })
                if limit == "executable_path_bytes"
        ));

        let mut over_argv = boundary.clone();
        let ProcessSpawnRequest::Run { launch, .. } = &mut over_argv else {
            unreachable!("boundary request is Run")
        };
        launch.argv.push(String::new());
        assert!(matches!(
            provider.preflight_request(&over_argv),
            Err(ProcessSpawnError::LimitExceeded { limit, .. }) if limit == "argv_count"
        ));

        let mut over_env = boundary.clone();
        let ProcessSpawnRequest::Run { launch, .. } = &mut over_env else {
            unreachable!("boundary request is Run")
        };
        launch.env.insert("X".to_string(), String::new());
        assert!(matches!(
            provider.preflight_request(&over_env),
            Err(ProcessSpawnError::LimitExceeded { limit, .. }) if limit == "env_count"
        ));

        let mut over_cwd = boundary.clone();
        let ProcessSpawnRequest::Run { launch, .. } = &mut over_cwd else {
            unreachable!("boundary request is Run")
        };
        launch.cwd = Some("cwdx".to_string());
        assert!(matches!(
            provider.preflight_request(&over_cwd),
            Err(ProcessSpawnError::LimitExceeded { limit, .. }) if limit == "cwd_bytes"
        ));

        let oversized_handle = ProcessSpawnRequest::CloseStdin {
            handle: "h".repeat(
                usize::try_from(provider.policy().limits.max_request_bytes)
                    .expect("test request limit fits usize"),
            ),
        };
        assert!(matches!(
            provider.preflight_request(&oversized_handle),
            Err(ProcessSpawnError::LimitExceeded { limit, .. })
                if limit == "request_bytes" || limit == "request_raw_bytes"
        ));
    }

    #[test]
    fn executable_image_limit_is_checked_before_authorization_hashing() {
        let directory = tempfile::tempdir().expect("create executable fixture directory");
        let executable = directory.path().join("oversized-image");
        std::fs::write(&executable, [0_u8; 2]).expect("write executable fixture");
        let mut policy = ProcessSpawnPolicy::jailed(directory.path()).expect("fixture policy");
        policy.limits.max_executable_bytes = 1;

        assert!(matches!(
            policy.authorize_executable(&executable),
            Err(ProcessSpawnError::LimitExceeded {
                limit,
                actual: 2,
                maximum: 1,
            }) if limit == "executable_bytes"
        ));
        assert!(policy.allowed_executables.is_empty());
    }

    #[cfg(unix)]
    #[test]
    fn detached_spawn_watchdog_reaps_when_live_control_stops() {
        let sleep = executable(&["/bin/sleep", "/usr/bin/sleep"]);
        let (provider, canonical) = provider_for(&sleep);
        let stopped = Arc::new(AtomicUsize::new(0));
        let control = Arc::new(TestStopControl {
            stopped: Arc::clone(&stopped),
        });
        let response = provider
            .perform_controlled(
                &ProcessSpawnRequest::Spawn {
                    launch: ProcessLaunch {
                        executable: canonical,
                        argv: vec!["30".to_string()],
                        env: BTreeMap::new(),
                        cwd: None,
                        shell: false,
                        stdio: ProcessStdio::default(),
                    },
                },
                &[ProcessSpawnCapability::Spawn],
                control,
            )
            .expect("spawn controlled sleep");
        let ProcessSpawnResponse::Spawned { handle } = response else {
            panic!("expected Spawned response")
        };
        stopped.store(1, Ordering::Release);
        for _ in 0..1_000 {
            if provider.active_watchdogs.load(Ordering::Acquire) == 0 {
                break;
            }
            thread::sleep(Duration::from_millis(2));
        }

        assert_eq!(provider.active_children.load(Ordering::Acquire), 0);
        assert_eq!(provider.active_watchdogs.load(Ordering::Acquire), 0);
        assert!(matches!(
            provider.perform(
                &ProcessSpawnRequest::Wait {
                    handle,
                    timeout_millis: Some(10),
                },
                &[ProcessSpawnCapability::Spawn],
            ),
            Err(ProcessSpawnError::Denied { reason })
                if reason == "TEST_PROCESS_CONTROL_STOPPED"
        ));
    }

    #[test]
    fn deny_all_rejects_every_operation() {
        let request = ProcessSpawnRequest::CloseStdin {
            handle: "opaque".to_string(),
        };
        assert!(matches!(
            DenyAllProcessSpawn.perform(&request, &[ProcessSpawnCapability::Spawn]),
            Err(ProcessSpawnError::Denied { .. })
        ));
    }

    #[test]
    fn typed_values_round_trip_through_serde() {
        let request = run_request("/canonical/program".to_string(), vec!["a", "b"]);
        let json = serde_json::to_string(&request).expect("serialize request");
        assert_eq!(
            request,
            serde_json::from_str::<ProcessSpawnRequest>(&json).expect("deserialize request")
        );
        let error = ProcessSpawnError::LimitExceeded {
            limit: "argv_bytes".to_string(),
            actual: 3,
            maximum: 2,
        };
        let json = serde_json::to_string(&error).expect("serialize error");
        assert_eq!(
            error,
            serde_json::from_str::<ProcessSpawnError>(&json).expect("deserialize error")
        );
    }

    #[test]
    fn executable_canonicalization_preserves_only_not_found_as_a_stable_discriminator() {
        let not_found = executable_canonicalize_error(std::io::Error::new(
            std::io::ErrorKind::NotFound,
            "missing executable",
        ));
        assert!(matches!(
            &not_found,
            ProcessSpawnError::Io { operation, detail }
                if operation == PROCESS_SPAWN_CANONICALIZE_EXECUTABLE_NOT_FOUND_OPERATION
                    && detail == "missing executable"
        ));
        let encoded = serde_json::to_value(&not_found).expect("serialize not-found error");
        assert_eq!(encoded["kind"], "io");
        assert_eq!(
            encoded["operation"],
            PROCESS_SPAWN_CANONICALIZE_EXECUTABLE_NOT_FOUND_OPERATION
        );
        assert_eq!(
            serde_json::from_value::<ProcessSpawnError>(encoded)
                .expect("deserialize not-found error"),
            not_found
        );

        let permission_denied = executable_canonicalize_error(std::io::Error::new(
            std::io::ErrorKind::PermissionDenied,
            "permission denied",
        ));
        assert!(matches!(
            permission_denied,
            ProcessSpawnError::Io { operation, detail }
                if operation == PROCESS_SPAWN_CANONICALIZE_EXECUTABLE_OTHER_IO_OPERATION
                    && detail == "permission denied"
        ));

        let spawn_not_found = executable_spawn_error(std::io::Error::new(
            std::io::ErrorKind::NotFound,
            "missing script interpreter",
        ));
        assert!(matches!(
            spawn_not_found,
            ProcessSpawnError::Io { operation, detail }
                if operation == PROCESS_SPAWN_EXECUTABLE_SPAWN_NOT_FOUND_OPERATION
                    && detail == "missing script interpreter"
        ));

        let spawn_permission_denied = executable_spawn_error(std::io::Error::new(
            std::io::ErrorKind::PermissionDenied,
            "spawn permission denied",
        ));
        assert!(matches!(
            spawn_permission_denied,
            ProcessSpawnError::Io { operation, detail }
                if operation == "spawn" && detail == "spawn permission denied"
        ));
    }

    #[test]
    fn process_diagnostics_redact_commands_payloads_and_handles() {
        let executable_secret = "/secret/executable-bd-x85a7-3";
        let argument_secret = "argument-secret-bd-x85a7-3";
        let env_key_secret = "ENV_KEY_SECRET_BD_X85A7_3";
        let env_value_secret = "env-value-secret-bd-x85a7-3";
        let cwd_secret = "/secret/cwd-bd-x85a7-3";
        let stdin_secret = "stdin-secret-bd-x85a7-3";
        let stdout_secret = "stdout-secret-bd-x85a7-3";
        let stderr_secret = "stderr-secret-bd-x85a7-3";
        let handle_secret = "opaque-handle-secret-bd-x85a7-3";
        let detail_secret = "diagnostic-detail-secret-bd-x85a7-3";
        let secrets = [
            executable_secret,
            argument_secret,
            env_key_secret,
            env_value_secret,
            cwd_secret,
            stdin_secret,
            stdout_secret,
            stderr_secret,
            handle_secret,
            detail_secret,
        ];
        let launch = ProcessLaunch {
            executable: executable_secret.to_string(),
            argv: vec![argument_secret.to_string()],
            env: BTreeMap::from([(env_key_secret.to_string(), env_value_secret.to_string())]),
            cwd: Some(cwd_secret.to_string()),
            shell: true,
            stdio: ProcessStdio::default(),
        };
        let request = ProcessSpawnRequest::Run {
            launch: launch.clone(),
            stdin: stdin_secret.as_bytes().to_vec(),
            timeout_millis: Some(123),
        };
        let response = ProcessSpawnResponse::Run {
            exit: ProcessExit {
                success: false,
                code: Some(7),
                signal: None,
            },
            stdout: stdout_secret.as_bytes().to_vec(),
            stderr: stderr_secret.as_bytes().to_vec(),
        };
        let handle_request = ProcessSpawnRequest::WriteStdin {
            handle: handle_secret.to_string(),
            data: stdin_secret.as_bytes().to_vec(),
        };
        let handle_response = ProcessSpawnResponse::Spawned {
            handle: handle_secret.to_string(),
        };
        let cleanup_request = ProcessSpawnRequest::Cleanup {
            handle: handle_secret.to_string(),
        };
        let cleanup_response = ProcessSpawnResponse::Cleaned { was_present: true };
        let errors = [
            ProcessSpawnError::Denied {
                reason: detail_secret.to_string(),
            },
            ProcessSpawnError::PolicyViolation {
                code: detail_secret.to_string(),
                detail: detail_secret.to_string(),
            },
            ProcessSpawnError::LimitExceeded {
                limit: detail_secret.to_string(),
                actual: 2,
                maximum: 1,
            },
            ProcessSpawnError::UnknownHandle {
                handle: handle_secret.to_string(),
            },
            ProcessSpawnError::InvalidState {
                detail: detail_secret.to_string(),
            },
            ProcessSpawnError::NotImplemented {
                what: detail_secret.to_string(),
            },
            ProcessSpawnError::Io {
                operation: detail_secret.to_string(),
                detail: detail_secret.to_string(),
            },
            ProcessSpawnError::ReplayDivergence {
                index: 4,
                live_kind: detail_secret.to_string(),
                recorded_kind: detail_secret.to_string(),
                live_request_digest: [8; 32],
                recorded_request_digest: Some([9; 32]),
            },
        ];
        let policy = ProcessSpawnPolicy {
            allowed_executables: BTreeMap::from([(executable_secret.to_string(), [7; 32])]),
            executable_aliases: BTreeMap::from([(
                argument_secret.to_string(),
                executable_secret.to_string(),
            )]),
            allow_shell: true,
            shell_executable_alias: Some(argument_secret.to_string()),
            allowed_env_keys: BTreeSet::from([env_key_secret.to_string()]),
            fixed_env: BTreeMap::from([(env_key_secret.to_string(), env_value_secret.to_string())]),
            jailed_cwd_root: cwd_secret.to_string(),
            ..ProcessSpawnPolicy::default()
        };
        let captured = CapturedOutput {
            bytes: stdout_secret.as_bytes().to_vec(),
            overflowed: false,
            maximum: 4096,
        };
        let validated = ValidatedLaunch {
            executable: PathBuf::from(executable_secret),
            executable_file: None,
            argv: vec![argument_secret.to_string()],
            env: BTreeMap::from([(env_key_secret.to_string(), env_value_secret.to_string())]),
            cwd: PathBuf::from(cwd_secret),
            stdio: ProcessStdio::default(),
        };
        let transcript = InMemoryProcessSpawnTranscript::replaying(vec![(
            request.clone(),
            Ok(response.clone()),
        )]);

        let mut rendered = vec![
            format!("{launch:?}"),
            format!("{request:?}"),
            format!("{response:?}"),
            format!("{handle_request:?}"),
            format!("{handle_response:?}"),
            format!("{cleanup_request:?}"),
            format!("{cleanup_response:?}"),
            format!("{policy:?}"),
            format!("{captured:?}"),
            format!("{validated:?}"),
            format!("{transcript:?}"),
        ];
        for error in &errors {
            rendered.push(format!("{error:?}"));
            rendered.push(error.to_string());
        }
        for diagnostic in &rendered {
            for secret in &secrets {
                assert!(
                    !diagnostic.contains(secret),
                    "diagnostic leaked secret {secret:?}: {diagnostic}"
                );
            }
        }
        assert!(rendered.iter().any(|value| value.contains("stdin_bytes")));
        assert!(rendered.iter().any(|value| value.contains("stdout_bytes")));
        assert!(rendered.iter().any(|value| value.contains("handle_bytes")));
    }

    #[test]
    fn redacted_diagnostics_do_not_change_canonical_serde() {
        let request = ProcessSpawnRequest::Run {
            launch: ProcessLaunch {
                executable: "/canonical/secret-command".to_string(),
                argv: vec!["secret-argument".to_string()],
                env: BTreeMap::from([("SECRET_KEY".to_string(), "secret-value".to_string())]),
                cwd: Some("/canonical/secret-cwd".to_string()),
                shell: false,
                stdio: ProcessStdio::default(),
            },
            stdin: b"secret-stdin".to_vec(),
            timeout_millis: Some(500),
        };
        let response = ProcessSpawnResponse::Run {
            exit: ProcessExit {
                success: true,
                code: Some(0),
                signal: None,
            },
            stdout: b"secret-stdout".to_vec(),
            stderr: b"secret-stderr".to_vec(),
        };
        let error = ProcessSpawnError::UnknownHandle {
            handle: "secret-handle".to_string(),
        };

        let request_json = serde_json::to_value(&request).expect("serialize request");
        assert_eq!(
            request_json["launch"]["executable"],
            "/canonical/secret-command"
        );
        assert_eq!(request_json["launch"]["argv"][0], "secret-argument");
        assert_eq!(request_json["launch"]["env"]["SECRET_KEY"], "secret-value");
        assert_eq!(request_json["stdin"], serde_json::json!(b"secret-stdin"));
        assert_eq!(
            serde_json::from_value::<ProcessSpawnRequest>(request_json)
                .expect("deserialize request"),
            request
        );

        let response_json = serde_json::to_value(&response).expect("serialize response");
        assert_eq!(response_json["stdout"], serde_json::json!(b"secret-stdout"));
        assert_eq!(response_json["stderr"], serde_json::json!(b"secret-stderr"));
        assert_eq!(
            serde_json::from_value::<ProcessSpawnResponse>(response_json)
                .expect("deserialize response"),
            response
        );

        let error_json = serde_json::to_value(&error).expect("serialize error");
        assert_eq!(error_json["handle"], "secret-handle");
        assert_eq!(
            serde_json::from_value::<ProcessSpawnError>(error_json).expect("deserialize error"),
            error
        );
    }

    #[test]
    fn empty_default_policy_cannot_install() {
        assert!(NativeProcessSpawn::new(ProcessSpawnPolicy::default()).is_err());
    }

    #[test]
    fn dangerous_loader_environment_is_never_accepted() {
        let mut policy = ProcessSpawnPolicy::jailed("/").expect("rooted policy");
        policy
            .fixed_env
            .insert("LD_PRELOAD".to_string(), "/tmp/inject.so".to_string());
        assert!(matches!(
            NativeProcessSpawn::new(policy),
            Err(ProcessSpawnError::PolicyViolation { ref code, .. }) if code == "dangerous_env"
        ));
    }

    #[cfg(unix)]
    #[test]
    fn policy_and_provider_debug_redact_policy_strings() {
        let echo = executable(&["/bin/echo", "/usr/bin/echo"]);
        let mut policy = ProcessSpawnPolicy::jailed("/").expect("rooted policy");
        policy.authorize_executable(&echo).expect("authorize echo");
        policy.fixed_env.insert(
            "API_TOKEN".to_string(),
            "never-print-this-secret".to_string(),
        );
        let policy_debug = format!("{policy:?}");
        assert!(!policy_debug.contains("API_TOKEN"));
        assert!(!policy_debug.contains("never-print-this-secret"));

        let provider = NativeProcessSpawn::new(policy).expect("native provider");
        let provider_debug = format!("{provider:?}");
        assert!(!provider_debug.contains("API_TOKEN"));
        assert!(!provider_debug.contains("never-print-this-secret"));
    }

    #[cfg(unix)]
    #[test]
    fn capability_and_executable_policy_fail_closed() {
        let echo = executable(&["/bin/echo", "/usr/bin/echo"]);
        let (provider, canonical) = provider_for(&echo);
        let request = run_request(canonical, vec!["hello"]);
        assert!(matches!(
            provider.perform(&request, &[]),
            Err(ProcessSpawnError::CapabilityMissing { .. })
        ));
        assert!(matches!(
            provider.perform(&run_request("missing".to_string(), Vec::new()), &[]),
            Err(ProcessSpawnError::CapabilityMissing { .. })
        ));

        let unlisted = executable(&["/bin/pwd", "/usr/bin/pwd"]);
        let unlisted = path_string(&unlisted).expect("utf8 path");
        assert!(matches!(
            provider.perform(
                &run_request(unlisted, Vec::new()),
                &[ProcessSpawnCapability::Spawn]
            ),
            Err(ProcessSpawnError::PolicyViolation { ref code, .. })
                if code == "executable_denied"
        ));
    }

    #[cfg(unix)]
    #[test]
    fn bounded_real_direct_command_runs_without_a_shell() {
        let echo = executable(&["/bin/echo", "/usr/bin/echo"]);
        let (provider, canonical) = provider_for(&echo);
        let response = provider
            .perform(
                &run_request(canonical, vec!["hello"]),
                &[ProcessSpawnCapability::Spawn],
            )
            .expect("run echo");
        assert!(matches!(
            response,
            ProcessSpawnResponse::Run {
                exit: ProcessExit { success: true, .. },
                ref stdout,
                ref stderr,
            } if stdout == b"hello\n" && stderr.is_empty()
        ));
    }

    #[cfg(any(target_os = "linux", target_os = "freebsd"))]
    #[test]
    fn verified_executable_file_survives_path_replacement() {
        let shell = executable(&["/bin/sh", "/usr/bin/sh"]);
        let echo = executable(&["/bin/echo", "/usr/bin/echo"]);
        let temporary = tempfile::tempdir().expect("temporary executable directory");
        let authorized_path = temporary.path().join("sh");
        let replacement_path = temporary.path().join("replacement");
        std::fs::copy(&shell, &authorized_path).expect("copy authorized executable");
        std::fs::copy(&echo, &replacement_path).expect("copy replacement executable");

        let mut policy =
            ProcessSpawnPolicy::jailed(temporary.path()).expect("temporary jailed policy");
        let canonical = policy
            .authorize_executable(&authorized_path)
            .expect("authorize copied executable");
        let provider = NativeProcessSpawn::new(policy).expect("native provider");
        let request = run_request(canonical, vec!["-c", "printf verified"]);
        let ProcessSpawnRequest::Run { launch, .. } = request else {
            unreachable!()
        };
        let validated = provider.validate_launch(&launch).expect("validated launch");

        std::fs::rename(&replacement_path, &authorized_path)
            .expect("replace the authorized pathname after validation");

        let permit = provider.reserve_child().expect("reserve child");
        let running = provider
            .spawn_validated(validated, permit)
            .expect("spawn verified executable file");
        let (exit, stdout, stderr) =
            wait_and_collect(running, Duration::from_secs(1)).expect("collect verified process");
        assert!(exit.success);
        assert_eq!(stdout, b"verified");
        assert!(stderr.is_empty());
    }

    #[cfg(unix)]
    #[test]
    fn legacy_recorder_refuses_live_alias_preparation_and_dispatch() {
        let echo = executable(&["/bin/echo", "/usr/bin/echo"]);
        let mut policy = ProcessSpawnPolicy::jailed("/").expect("rooted policy");
        let canonical = policy
            .authorize_alias("echo", &echo)
            .expect("authorize alias");
        let provider = NativeProcessSpawn::new(policy).expect("native provider");
        let recorder = InMemoryProcessSpawnTranscript::recording();
        recorder.begin_execution().expect("begin recording");
        let request = run_request("echo".to_string(), vec!["aliased"]);
        assert!(matches!(
            perform_recorded(
                &provider,
                Some(&recorder),
                &request,
                &[ProcessSpawnCapability::Spawn],
            ),
            Err(ProcessSpawnError::Denied { .. })
        ));
        let current = recorder.finish_execution().expect("finish recording");
        let ProcessSpawnRequest::Run { launch, .. } = &current[0].0 else {
            panic!("run transcript");
        };
        assert_eq!(launch.executable, "echo");
        assert_ne!(launch.executable, canonical);
        assert!(matches!(
            &current[0].1,
            Err(ProcessSpawnError::Denied { .. })
        ));

        assert!(matches!(
            provider.perform(
                &run_request("missing".to_string(), Vec::new()),
                &[ProcessSpawnCapability::Spawn],
            ),
            Err(ProcessSpawnError::PolicyViolation { ref code, .. })
                if code == "executable_alias_denied"
        ));
    }

    #[cfg(unix)]
    #[test]
    fn output_overflow_is_drained_then_rejected() {
        let echo = executable(&["/bin/echo", "/usr/bin/echo"]);
        let mut policy = ProcessSpawnPolicy::jailed("/").expect("rooted policy");
        let canonical = policy.authorize_executable(&echo).expect("authorize echo");
        policy.limits.max_output_bytes = 4;
        let provider = NativeProcessSpawn::new(policy).expect("native provider");
        assert!(matches!(
            provider.perform(
                &run_request(canonical, vec!["too-long"]),
                &[ProcessSpawnCapability::Spawn],
            ),
            Err(ProcessSpawnError::PartialOutputFailed {
                ref failure,
                signal: None,
                ref partial_stdout,
                ref partial_stderr,
            }) if matches!(
                failure.as_ref(),
                ProcessSpawnError::LimitExceeded {
                    limit,
                    maximum: 4,
                    ..
                } if limit == "stdout_bytes"
            ) && partial_stdout == b"too-"
                && partial_stderr.is_empty()
        ));
        assert_eq!(provider.active_children.load(Ordering::Acquire), 0);
    }

    #[cfg(unix)]
    #[test]
    fn shell_env_and_cwd_require_explicit_policy() {
        let pwd = executable(&["/bin/pwd", "/usr/bin/pwd"]);
        let (provider, canonical) = provider_for(&pwd);
        let mut request = run_request(canonical, Vec::new());
        if let ProcessSpawnRequest::Run { launch, .. } = &mut request {
            launch.shell = true;
        }
        assert!(matches!(
            provider.perform(&request, &[ProcessSpawnCapability::Spawn]),
            Err(ProcessSpawnError::PolicyViolation { ref code, .. }) if code == "shell_denied"
        ));
        if let ProcessSpawnRequest::Run { launch, .. } = &mut request {
            launch.shell = false;
            launch.env.insert("SECRET".to_string(), "leak".to_string());
        }
        assert!(matches!(
            provider.perform(&request, &[ProcessSpawnCapability::Spawn]),
            Err(ProcessSpawnError::PolicyViolation { ref code, .. }) if code == "env_key_denied"
        ));
    }

    #[cfg(unix)]
    #[test]
    fn shell_opt_in_uses_only_the_signed_shell_alias_and_canonical_protocol() {
        let shell = executable(&["/bin/sh", "/usr/bin/sh"]);
        let mut policy = ProcessSpawnPolicy::jailed("/").expect("rooted policy");
        let canonical = policy
            .authorize_alias("system-shell", &shell)
            .expect("authorize shell alias");
        policy.allow_shell = true;
        policy.shell_executable_alias = Some("system-shell".to_string());
        let provider = NativeProcessSpawn::new(policy).expect("native provider");

        let mut malformed = run_request(canonical.clone(), vec!["printf shell"]);
        if let ProcessSpawnRequest::Run { launch, .. } = &mut malformed {
            launch.shell = true;
        }
        assert!(matches!(
            provider.perform(&malformed, &[ProcessSpawnCapability::Spawn]),
            Err(ProcessSpawnError::PolicyViolation { ref code, .. })
                if code == "shell_caller_selection"
        ));

        let mut exact = run_request(String::new(), vec!["printf shell-ok"]);
        if let ProcessSpawnRequest::Run { launch, .. } = &mut exact {
            launch.shell = true;
        }
        let prepared = provider.prepare_request(&exact).expect("prepare shell");
        let ProcessSpawnRequest::Run {
            launch: prepared_launch,
            ..
        } = &prepared
        else {
            panic!("prepared run");
        };
        assert_eq!(prepared_launch.executable, canonical);
        assert_eq!(prepared_launch.argv, ["-c", "printf shell-ok"]);
        assert!(matches!(
            provider.perform(&exact, &[ProcessSpawnCapability::Spawn]),
            Ok(ProcessSpawnResponse::Run { ref stdout, .. }) if stdout == b"shell-ok"
        ));
    }

    #[cfg(unix)]
    #[test]
    fn cwd_is_confined_to_the_canonical_jail() {
        let pwd = executable(&["/bin/pwd", "/usr/bin/pwd"]);
        let mut policy = ProcessSpawnPolicy::jailed("/tmp").expect("tmp jail");
        let canonical = policy.authorize_executable(&pwd).expect("authorize pwd");
        let provider = NativeProcessSpawn::new(policy).expect("native provider");
        let mut request = run_request(canonical, Vec::new());
        if let ProcessSpawnRequest::Run { launch, .. } = &mut request {
            launch.cwd = Some("/".to_string());
        }
        assert!(matches!(
            provider.perform(&request, &[ProcessSpawnCapability::Spawn]),
            Err(ProcessSpawnError::PolicyViolation { ref code, .. }) if code == "cwd_escape"
        ));
    }

    #[cfg(unix)]
    #[test]
    fn piped_stdin_and_fixed_environment_are_real_and_bounded() {
        let env = executable(&["/usr/bin/env", "/bin/env"]);
        let mut policy = ProcessSpawnPolicy::jailed("/").expect("rooted policy");
        let canonical = policy.authorize_executable(&env).expect("authorize env");
        policy
            .fixed_env
            .insert("FRANKEN_FIXED".to_string(), "yes".to_string());
        let provider = NativeProcessSpawn::new(policy).expect("native provider");
        let response = provider
            .perform(
                &run_request(canonical, Vec::new()),
                &[ProcessSpawnCapability::Spawn],
            )
            .expect("run env");
        let ProcessSpawnResponse::Run { stdout, .. } = response else {
            panic!("run response");
        };
        assert_eq!(stdout, b"FRANKEN_FIXED=yes\n");

        let cat = executable(&["/bin/cat", "/usr/bin/cat"]);
        let (provider, canonical) = provider_for(&cat);
        let mut request = run_request(canonical, Vec::new());
        let ProcessSpawnRequest::Run { stdin, .. } = &mut request else {
            unreachable!()
        };
        *stdin = b"bounded input".to_vec();
        assert!(matches!(
            provider.perform(&request, &[ProcessSpawnCapability::Spawn]),
            Ok(ProcessSpawnResponse::Run { ref stdout, .. }) if stdout == b"bounded input"
        ));
    }

    #[cfg(unix)]
    #[test]
    fn timeout_kills_and_reaps_run() {
        let sleep = executable(&["/bin/sleep", "/usr/bin/sleep"]);
        let (provider, canonical) = provider_for(&sleep);
        let mut request = run_request(canonical, vec!["5"]);
        let ProcessSpawnRequest::Run { timeout_millis, .. } = &mut request else {
            unreachable!()
        };
        *timeout_millis = Some(10);
        assert!(matches!(
            provider.perform(&request, &[ProcessSpawnCapability::Spawn]),
            Err(ProcessSpawnError::PartialOutputFailed { failure, .. })
                if matches!(failure.as_ref(), ProcessSpawnError::TimedOut { .. })
        ));
        assert_eq!(provider.active_children.load(Ordering::Acquire), 0);
    }

    #[cfg(unix)]
    #[test]
    fn run_timeout_retains_partial_streams_and_terminating_signal() {
        let shell = executable(&["/bin/sh", "/usr/bin/sh"]);
        let (provider, canonical) = provider_for(&shell);
        let mut request = run_request(
            canonical,
            vec![
                "-c",
                "echo partial-stdout-marker; echo partial-stderr-marker >&2; sleep 30",
            ],
        );
        let ProcessSpawnRequest::Run { timeout_millis, .. } = &mut request else {
            unreachable!()
        };
        // Long enough that both drain threads have certainly captured the
        // echoes before containment fires; short enough to keep the suite fast.
        *timeout_millis = Some(300);
        let stdout_marker = b"partial-stdout-marker";
        let stderr_marker = b"partial-stderr-marker";
        assert!(matches!(
            provider.perform(&request, &[ProcessSpawnCapability::Spawn]),
            Err(ProcessSpawnError::PartialOutputFailed {
                failure,
                signal: Some(9),
                ref partial_stdout,
                ref partial_stderr,
            }) if matches!(failure.as_ref(), ProcessSpawnError::TimedOut { .. })
                && partial_stdout.windows(stdout_marker.len()).any(|w| w == stdout_marker)
                && partial_stderr.windows(stderr_marker.len()).any(|w| w == stderr_marker)
        ));
        assert_eq!(provider.active_children.load(Ordering::Acquire), 0);
    }

    #[cfg(unix)]
    #[test]
    fn capture_cap_retains_prefix_bytes_on_limit_failure() {
        let shell = executable(&["/bin/sh", "/usr/bin/sh"]);
        let mut policy = ProcessSpawnPolicy::jailed("/").expect("rooted policy");
        let canonical = policy.authorize_executable(&shell).expect("authorize sh");
        policy.limits.max_output_bytes = 16;
        let provider = NativeProcessSpawn::new(policy).expect("native provider");
        let mut request = run_request(
            canonical,
            vec!["-c", "printf 0123456789abcdef0123456789abcdef"],
        );
        let ProcessSpawnRequest::Run { timeout_millis, .. } = &mut request else {
            unreachable!()
        };
        *timeout_millis = Some(5_000);
        assert!(matches!(
            provider.perform(&request, &[ProcessSpawnCapability::Spawn]),
            Err(ProcessSpawnError::PartialOutputFailed {
                failure,
                signal: None,
                ref partial_stdout,
                ref partial_stderr,
            }) if matches!(
                failure.as_ref(),
                ProcessSpawnError::LimitExceeded {
                    limit,
                    actual: 17,
                    maximum: 16,
                    ..
                } if limit == "stdout_bytes"
            ) && partial_stdout == b"0123456789abcdef"
                && partial_stderr.is_empty()
        ));
        assert_eq!(provider.active_children.load(Ordering::Acquire), 0);
    }

    #[test]
    fn partial_output_failed_round_trips_through_serialization() {
        let error = ProcessSpawnError::PartialOutputFailed {
            failure: Box::new(ProcessSpawnError::TimedOut { runtime_millis: 42 }),
            signal: Some(9),
            partial_stdout: b"captured-out".to_vec(),
            partial_stderr: b"captured-err".to_vec(),
        };
        let encoded = serde_json::to_string(&error).expect("serialize typed process failure");
        let decoded: ProcessSpawnError =
            serde_json::from_str(&encoded).expect("deserialize typed process failure");
        assert_eq!(decoded, error);
    }

    #[test]
    fn legacy_timeout_records_still_deserialize_without_partial_fields() {
        let decoded: ProcessSpawnError =
            serde_json::from_str(r#"{"kind":"timed_out","runtime_millis":7}"#)
                .expect("legacy timed_out shape stays readable");
        assert_eq!(decoded, ProcessSpawnError::TimedOut { runtime_millis: 7 });
    }

    #[test]
    fn partial_output_failed_formatting_never_embeds_captured_bytes() {
        let secret_stdout = b"TOPSECRET-PARTIAL-STDOUT".to_vec();
        let secret_stderr = b"TOPSECRET-PARTIAL-STDERR".to_vec();
        let error = ProcessSpawnError::PartialOutputFailed {
            failure: Box::new(ProcessSpawnError::Io {
                operation: "poll child".to_string(),
                detail: "fixture".to_string(),
            }),
            signal: Some(9),
            partial_stdout: secret_stdout,
            partial_stderr: secret_stderr,
        };
        let debug = format!("{error:?}");
        let display = format!("{error}");
        assert!(!debug.contains("TOPSECRET-PARTIAL"));
        assert!(!display.contains("TOPSECRET-PARTIAL"));
        assert!(debug.contains("partial_stdout_len"));
        assert!(debug.contains("partial_stderr_len"));
    }

    #[cfg(unix)]
    #[test]
    fn lifecycle_stdin_write_end_round_trips_through_cat_bd_m42c2() {
        let cat = executable(&["/bin/cat", "/usr/bin/cat"]);
        let mut policy = ProcessSpawnPolicy::jailed("/").expect("rooted policy");
        let canonical = policy.authorize_executable(&cat).expect("authorize cat");
        policy.limits.max_stdin_bytes = 1024;
        let provider = NativeProcessSpawn::new(policy).expect("native provider");
        let response = provider
            .perform(
                &ProcessSpawnRequest::Spawn {
                    launch: ProcessLaunch {
                        executable: canonical,
                        argv: Vec::new(),
                        env: BTreeMap::new(),
                        cwd: None,
                        shell: false,
                        stdio: ProcessStdio::default(),
                    },
                },
                &[ProcessSpawnCapability::Spawn],
            )
            .expect("spawn cat for stdin round trip");
        let ProcessSpawnResponse::Spawned { handle } = response else {
            panic!("lifecycle spawn response");
        };
        assert!(matches!(
            provider.perform(
                &ProcessSpawnRequest::WriteStdin {
                    handle: handle.clone(),
                    data: b"through-stdin".to_vec(),
                },
                &[ProcessSpawnCapability::Spawn],
            ),
            Ok(ProcessSpawnResponse::StdinWritten { bytes_written: 13 })
        ));
        assert!(matches!(
            provider.perform(
                &ProcessSpawnRequest::CloseStdin {
                    handle: handle.clone(),
                },
                &[ProcessSpawnCapability::Spawn],
            ),
            Ok(ProcessSpawnResponse::StdinClosed)
        ));
        assert!(matches!(
            provider.perform(
                &ProcessSpawnRequest::Wait {
                    handle,
                    timeout_millis: Some(5_000),
                },
                &[ProcessSpawnCapability::Spawn],
            ),
            Ok(ProcessSpawnResponse::Waited {
                exit: ProcessExit {
                    success: true,
                    ..
                },
                stdout,
                ..
            }) if stdout == b"through-stdin"
        ));
    }

    #[cfg(unix)]
    #[test]
    fn bounded_stdin_enforces_the_cumulative_limit_bd_m42c2() {
        let cat = executable(&["/bin/cat", "/usr/bin/cat"]);
        let mut policy = ProcessSpawnPolicy::jailed("/").expect("rooted policy");
        let canonical = policy.authorize_executable(&cat).expect("authorize cat");
        policy.limits.max_stdin_bytes = 8;
        let provider = NativeProcessSpawn::new(policy).expect("native provider");
        let response = provider
            .perform(
                &ProcessSpawnRequest::Spawn {
                    launch: ProcessLaunch {
                        executable: canonical,
                        argv: Vec::new(),
                        env: BTreeMap::new(),
                        cwd: None,
                        shell: false,
                        stdio: ProcessStdio::default(),
                    },
                },
                &[ProcessSpawnCapability::Spawn],
            )
            .expect("spawn cat for stdin bound");
        let ProcessSpawnResponse::Spawned { handle } = response else {
            panic!("lifecycle spawn response");
        };
        assert!(matches!(
            provider.perform(
                &ProcessSpawnRequest::WriteStdin {
                    handle: handle.clone(),
                    data: vec![b'a'; 6],
                },
                &[ProcessSpawnCapability::Spawn],
            ),
            Ok(ProcessSpawnResponse::StdinWritten { bytes_written: 6 })
        ));
        assert!(matches!(
            provider.perform(
                &ProcessSpawnRequest::WriteStdin {
                    handle,
                    data: vec![b'b'; 3],
                },
                &[ProcessSpawnCapability::Spawn],
            ),
            Err(ProcessSpawnError::LimitExceeded {
                limit,
                actual: 9,
                maximum: 8,
                ..
            }) if limit == "stdin_bytes"
        ));
    }

    #[cfg(unix)]
    #[test]
    fn kill_with_terminate_signals_the_group_and_reports_sigterm_bd_m42c2() {
        let sleep = executable(&["/bin/sleep", "/usr/bin/sleep"]);
        let mut policy = ProcessSpawnPolicy::jailed("/").expect("rooted policy");
        let canonical = policy
            .authorize_executable(&sleep)
            .expect("authorize sleep");
        policy.allowed_signals.insert(ProcessSignal::Terminate);
        let provider = NativeProcessSpawn::new(policy).expect("native provider");
        let response = provider
            .perform(
                &ProcessSpawnRequest::Spawn {
                    launch: ProcessLaunch {
                        executable: canonical,
                        argv: vec!["30".to_string()],
                        env: BTreeMap::new(),
                        cwd: None,
                        shell: false,
                        stdio: ProcessStdio::default(),
                    },
                },
                &[ProcessSpawnCapability::Spawn],
            )
            .expect("spawn sleep for terminate");
        let ProcessSpawnResponse::Spawned { handle } = response else {
            panic!("lifecycle spawn response");
        };
        assert!(matches!(
            provider.perform(
                &ProcessSpawnRequest::Kill {
                    handle: handle.clone(),
                    signal: ProcessSignal::Terminate,
                },
                &[ProcessSpawnCapability::Spawn],
            ),
            Ok(ProcessSpawnResponse::Killed {
                signal: ProcessSignal::Terminate,
                exit: ProcessExit {
                    success: false,
                    code: None,
                    signal: Some(15),
                },
                ..
            })
        ));
        // bd-m42c2: the terminal kill outcome stays addressable so the
        // pending lifecycle Wait observes it instead of an unknown handle.
        assert!(matches!(
            provider.perform(
                &ProcessSpawnRequest::Wait {
                    handle,
                    timeout_millis: Some(1_000),
                },
                &[ProcessSpawnCapability::Spawn],
            ),
            Ok(ProcessSpawnResponse::Killed {
                signal: ProcessSignal::Terminate,
                ..
            })
        ));
        assert_eq!(provider.active_children.load(Ordering::Acquire), 0);
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn exited_child_descendant_cannot_hold_capture_pipes_or_escape_group_teardown() {
        let shell = executable(&["/bin/sh", "/usr/bin/sh"]);
        let sleep = executable(&["/bin/sleep", "/usr/bin/sleep"]);
        let (provider, canonical_shell) = provider_for(&shell);
        let command = format!("{} 5 & echo $!", sleep.display());
        let started = Instant::now();
        let response = provider
            .perform(
                &run_request(canonical_shell, vec!["-c", &command]),
                &[ProcessSpawnCapability::Spawn],
            )
            .expect("bounded process-group run");
        assert!(
            started.elapsed() < Duration::from_secs(2),
            "a descendant inheriting stdout must not hold Run open"
        );
        let ProcessSpawnResponse::Run { stdout, .. } = response else {
            panic!("run response");
        };
        let descendant = String::from_utf8(stdout)
            .expect("shell pid output")
            .trim()
            .parse::<u32>()
            .expect("descendant pid");
        let proc_entry = PathBuf::from(format!("/proc/{descendant}"));
        for _ in 0..100 {
            if !proc_entry.exists() {
                break;
            }
            thread::sleep(Duration::from_millis(5));
        }
        assert!(
            !proc_entry.exists(),
            "ordinary descendants in the private process group must be terminated"
        );
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn exited_child_descendant_cannot_escape_by_redirecting_capture_pipes() {
        let shell = executable(&["/bin/sh", "/usr/bin/sh"]);
        let sleep = executable(&["/bin/sleep", "/usr/bin/sleep"]);
        let (provider, canonical_shell) = provider_for(&shell);
        let command = format!("{} 5 >/dev/null 2>&1 & echo $!", sleep.display());
        let response = provider
            .perform(
                &run_request(canonical_shell, vec!["-c", &command]),
                &[ProcessSpawnCapability::Spawn],
            )
            .expect("redirected descendant must remain inside the private process group");
        let ProcessSpawnResponse::Run { stdout, .. } = response else {
            panic!("run response");
        };
        let descendant = String::from_utf8(stdout)
            .expect("shell pid output")
            .trim()
            .parse::<u32>()
            .expect("descendant pid");
        let proc_entry = PathBuf::from(format!("/proc/{descendant}"));
        for _ in 0..100 {
            if !proc_entry.exists() {
                break;
            }
            thread::sleep(Duration::from_millis(5));
        }
        assert!(
            !proc_entry.exists(),
            "a same-group descendant must be terminated even after closing inherited pipes"
        );
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn cancellation_during_post_exit_output_drain_remains_the_primary_outcome() {
        let shell = executable(&["/bin/sh", "/usr/bin/sh"]);
        let setsid = executable(&["/usr/bin/setsid", "/bin/setsid"]);
        let sleep = executable(&["/bin/sleep", "/usr/bin/sleep"]);
        let (provider, canonical_shell) = provider_for(&shell);
        let temp_dir = tempfile::tempdir().expect("create drain-cancellation marker directory");
        let marker = temp_dir.path().join("direct-child-exiting");
        let escaped_ready = temp_dir.path().join("escaped-session-ready");
        let command = format!(
            "{} {} -c 'echo ready > {}; exec {} 0.5' & escaped_pid=$!; \
             i=0; while [ ! -f {} ] && [ $i -lt 100 ]; do {} 0.01; i=$((i+1)); done; \
             [ -f {} ] || exit 97; echo $escaped_pid > {}",
            setsid.display(),
            shell.display(),
            escaped_ready.display(),
            sleep.display(),
            escaped_ready.display(),
            sleep.display(),
            escaped_ready.display(),
            marker.display()
        );
        let stopped = Arc::new(AtomicUsize::new(0));
        let stop_after_parent_exit = {
            let marker = marker.clone();
            let stopped = Arc::clone(&stopped);
            thread::spawn(move || {
                for _ in 0..1_000 {
                    if marker.is_file() {
                        // The shell writes the marker immediately before
                        // exiting. Give the direct child ample time to reap so
                        // the stop is observed in the bounded drain phase.
                        thread::sleep(Duration::from_millis(50));
                        stopped.store(1, Ordering::Release);
                        return;
                    }
                    thread::sleep(Duration::from_millis(1));
                }
                panic!("shell must publish the drain-cancellation marker");
            })
        };
        let outcome = provider.perform_controlled(
            &run_request(canonical_shell, vec!["-c", &command]),
            &[ProcessSpawnCapability::Spawn],
            Arc::new(TestStopControl {
                stopped: Arc::clone(&stopped),
            }),
        );
        stop_after_parent_exit
            .join()
            .expect("drain-cancellation controller must not panic");
        assert!(matches!(
            outcome,
            Err(ProcessSpawnError::Denied { reason })
                if reason == "TEST_PROCESS_CONTROL_STOPPED"
        ));
    }

    #[cfg(unix)]
    #[test]
    fn zero_timeout_uses_the_policy_deadline_instead_of_immediate_expiry() {
        let sleep = executable(&["/bin/sleep", "/usr/bin/sleep"]);
        let mut policy = ProcessSpawnPolicy::jailed("/").expect("rooted policy");
        let canonical = policy
            .authorize_executable(&sleep)
            .expect("authorize sleep");
        policy.limits.max_runtime_millis = 500;
        let provider = NativeProcessSpawn::new(policy).expect("native provider");
        let mut request = run_request(canonical, vec!["0.05"]);
        let ProcessSpawnRequest::Run { timeout_millis, .. } = &mut request else {
            unreachable!()
        };
        *timeout_millis = Some(0);
        assert!(matches!(
            provider.perform(&request, &[ProcessSpawnCapability::Spawn]),
            Ok(ProcessSpawnResponse::Run {
                exit: ProcessExit { success: true, .. },
                ..
            })
        ));
    }

    #[cfg(unix)]
    #[test]
    fn no_reader_cannot_block_run_stdin_past_timeout() {
        let sleep = executable(&["/bin/sleep", "/usr/bin/sleep"]);
        let mut policy = ProcessSpawnPolicy::jailed("/").expect("rooted policy");
        let canonical = policy
            .authorize_executable(&sleep)
            .expect("authorize sleep");
        policy.limits.max_stdin_bytes = 1024 * 1024;
        let provider = NativeProcessSpawn::new(policy).expect("native provider");
        let mut request = run_request(canonical, vec!["5"]);
        let ProcessSpawnRequest::Run {
            stdin,
            timeout_millis,
            ..
        } = &mut request
        else {
            unreachable!()
        };
        // Exceed an ordinary Linux pipe capacity while keeping the test's
        // preflight serialization cost well below the teardown deadline.
        *stdin = vec![b'x'; 128 * 1024];
        *timeout_millis = Some(10);
        let started = Instant::now();
        assert!(matches!(
            provider.perform(&request, &[ProcessSpawnCapability::Spawn]),
            Err(ProcessSpawnError::PartialOutputFailed { failure, .. })
                if matches!(failure.as_ref(), ProcessSpawnError::TimedOut { .. })
        ));
        assert!(started.elapsed() < Duration::from_secs(2));
        assert_eq!(provider.active_children.load(Ordering::Acquire), 0);
    }

    #[cfg(unix)]
    #[test]
    fn watchdog_timeout_remains_observable_until_wait_consumes_it() {
        let sleep = executable(&["/bin/sleep", "/usr/bin/sleep"]);
        let mut policy = ProcessSpawnPolicy::jailed("/").expect("rooted policy");
        let canonical = policy
            .authorize_executable(&sleep)
            .expect("authorize sleep");
        policy.limits.max_runtime_millis = 10;
        let provider = NativeProcessSpawn::new(policy).expect("native provider");
        let response = provider
            .perform(
                &ProcessSpawnRequest::Spawn {
                    launch: ProcessLaunch {
                        executable: canonical,
                        argv: vec!["5".to_string()],
                        env: BTreeMap::new(),
                        cwd: None,
                        shell: false,
                        stdio: ProcessStdio::default(),
                    },
                },
                &[ProcessSpawnCapability::Spawn],
            )
            .expect("spawn sleep");
        let ProcessSpawnResponse::Spawned { handle } = response else {
            panic!("spawned response");
        };
        thread::sleep(Duration::from_millis(50));
        assert!(matches!(
            provider.perform(
                &ProcessSpawnRequest::Wait {
                    handle,
                    timeout_millis: None,
                },
                &[ProcessSpawnCapability::Spawn],
            ),
            Err(ProcessSpawnError::PartialOutputFailed { failure, .. })
                if matches!(failure.as_ref(), ProcessSpawnError::TimedOut { .. })
        ));
    }

    #[cfg(unix)]
    #[test]
    fn lifecycle_kill_reaps_and_invalidates_opaque_handle() {
        let sleep = executable(&["/bin/sleep", "/usr/bin/sleep"]);
        let (provider, canonical) = provider_for(&sleep);
        let response = provider
            .perform(
                &ProcessSpawnRequest::Spawn {
                    launch: ProcessLaunch {
                        executable: canonical,
                        argv: vec!["5".to_string()],
                        env: BTreeMap::new(),
                        cwd: None,
                        shell: false,
                        stdio: ProcessStdio::default(),
                    },
                },
                &[ProcessSpawnCapability::Spawn],
            )
            .expect("spawn sleep");
        let ProcessSpawnResponse::Spawned { handle } = response else {
            panic!("spawned response");
        };
        assert!(matches!(
            provider.perform(
                &ProcessSpawnRequest::WriteStdin {
                    handle: handle.clone(),
                    data: b"would block".to_vec(),
                },
                &[ProcessSpawnCapability::Spawn],
            ),
            Ok(ProcessSpawnResponse::StdinWritten { bytes_written: 11 })
        ));
        assert!(handle.starts_with("ps-"));
        assert!(!handle.contains(&std::process::id().to_string()));
        let kill = provider.perform(
            &ProcessSpawnRequest::Kill {
                handle: handle.clone(),
                signal: ProcessSignal::Kill,
            },
            &[ProcessSpawnCapability::Spawn],
        );
        assert!(
            matches!(kill, Ok(ProcessSpawnResponse::Killed { .. })),
            "unexpected lifecycle kill outcome: {kill:?}"
        );
        // bd-m42c2: the kill outcome stays terminal-addressable so a pending
        // lifecycle Wait observes it rather than losing the handle.
        assert!(matches!(
            provider.perform(
                &ProcessSpawnRequest::Wait {
                    handle,
                    timeout_millis: Some(10),
                },
                &[ProcessSpawnCapability::Spawn],
            ),
            Ok(ProcessSpawnResponse::Killed { .. })
        ));
        assert_eq!(provider.active_children.load(Ordering::Acquire), 0);
        for _ in 0..100 {
            if provider.active_watchdogs.load(Ordering::Acquire) == 0 {
                break;
            }
            thread::sleep(Duration::from_millis(2));
        }
        assert_eq!(
            provider.active_watchdogs.load(Ordering::Acquire),
            0,
            "lifecycle completion must cancel its deadline watchdog"
        );
    }

    #[cfg(unix)]
    #[test]
    fn teardown_cleanup_reaps_without_guest_kill_authority() {
        let sleep = executable(&["/bin/sleep", "/usr/bin/sleep"]);
        let (provider, canonical) = provider_for(&sleep);
        let response = provider
            .perform(
                &ProcessSpawnRequest::Spawn {
                    launch: ProcessLaunch {
                        executable: canonical,
                        argv: vec!["5".to_string()],
                        env: BTreeMap::new(),
                        cwd: None,
                        shell: false,
                        stdio: ProcessStdio::default(),
                    },
                },
                &[ProcessSpawnCapability::Spawn],
            )
            .expect("spawn sleep");
        let ProcessSpawnResponse::Spawned { handle } = response else {
            panic!("spawned response");
        };

        assert!(matches!(
            provider.cleanup_handle(&handle),
            Ok(ProcessSpawnResponse::Cleaned { was_present: true })
        ));

        assert!(matches!(
            provider.perform(
                &ProcessSpawnRequest::Wait {
                    handle,
                    timeout_millis: Some(10),
                },
                &[ProcessSpawnCapability::Spawn],
            ),
            Err(ProcessSpawnError::UnknownHandle { .. })
        ));
        assert_eq!(provider.active_children.load(Ordering::Acquire), 0);
        for _ in 0..100 {
            if provider.active_watchdogs.load(Ordering::Acquire) == 0 {
                break;
            }
            thread::sleep(Duration::from_millis(2));
        }
        assert_eq!(provider.active_watchdogs.load(Ordering::Acquire), 0);
    }

    #[test]
    fn exact_replay_never_calls_live_provider() {
        let request = ProcessSpawnRequest::Kill {
            handle: "recorded-handle".to_string(),
            signal: ProcessSignal::Kill,
        };
        let response = Ok(ProcessSpawnResponse::Killed {
            signal: ProcessSignal::Kill,
            exit: ProcessExit {
                success: false,
                code: None,
                signal: Some(9),
            },
            stdout: Vec::new(),
            stderr: Vec::new(),
        });
        let transcript =
            InMemoryProcessSpawnTranscript::replaying(vec![(request.clone(), response.clone())]);
        transcript.begin_execution().expect("begin replay");
        assert_eq!(
            perform_recorded(
                &DenyAllProcessSpawn,
                Some(&transcript),
                &request,
                &[ProcessSpawnCapability::Spawn],
            ),
            response
        );
        assert_eq!(
            transcript.finish_execution().expect("finish replay").len(),
            1
        );
    }

    #[test]
    fn replay_mismatch_poisoning_and_unused_suffix_fail_closed() {
        let recorded = ProcessSpawnRequest::CloseStdin {
            handle: "one".to_string(),
        };
        let transcript = InMemoryProcessSpawnTranscript::replaying(vec![(
            recorded.clone(),
            Ok(ProcessSpawnResponse::StdinClosed),
        )]);
        transcript.begin_execution().expect("begin replay");
        let live = ProcessSpawnRequest::CloseStdin {
            handle: "different".to_string(),
        };
        let mismatch = transcript
            .replay(&live)
            .expect("replay outcome")
            .expect_err("mismatch");
        assert!(matches!(
            &mismatch,
            ProcessSpawnError::ReplayDivergence {
                live_request_digest,
                recorded_request_digest: Some(recorded_request_digest),
                ..
            } if live_request_digest == &process_spawn_request_digest(&live)
                && recorded_request_digest == &process_spawn_request_digest(&recorded)
        ));
        assert_eq!(transcript.finish_execution(), Err(mismatch));

        let unused = InMemoryProcessSpawnTranscript::replaying(vec![(
            live,
            Ok(ProcessSpawnResponse::StdinClosed),
        )]);
        unused.begin_execution().expect("begin replay");
        assert!(unused.finish_execution().is_err());
    }
}
