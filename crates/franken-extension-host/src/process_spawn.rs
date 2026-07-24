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
//! verifies the canonical executable and its SHA-256 digest immediately before
//! every launch, bounds input/output/runtime, and exposes only provider-scoped
//! opaque handles (never native process identifiers).

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
use std::sync::mpsc::{SyncSender, sync_channel};
use std::sync::{Arc, Mutex, MutexGuard, Weak};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

#[cfg(unix)]
use std::os::fd::AsFd;
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
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
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
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
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
        }
    }

    #[must_use]
    pub const fn required_capability(&self) -> ProcessSpawnCapability {
        ProcessSpawnCapability::Spawn
    }
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
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
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
}

/// Stable fail-closed errors for process effects.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
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
    },
}

impl fmt::Display for ProcessSpawnError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Denied { reason } => write!(f, "process spawn denied: {reason}"),
            Self::FlowPolicyBlocked => {
                write!(f, "process spawn denied: FLOW_POLICY_BLOCKED")
            }
            Self::CapabilityMissing { capability } => {
                write!(f, "process capability missing: {}", capability.as_str())
            }
            Self::PolicyViolation { code, detail } => {
                write!(f, "process policy violation {code}: {detail}")
            }
            Self::LimitExceeded {
                limit,
                actual,
                maximum,
            } => write!(f, "process limit {limit} exceeded: {actual} > {maximum}"),
            Self::UnknownHandle { handle } => write!(f, "unknown process handle: {handle}"),
            Self::InvalidState { detail } => write!(f, "invalid process state: {detail}"),
            Self::NotImplemented { what } => {
                write!(f, "process operation not implemented: {what}")
            }
            Self::TimedOut { runtime_millis } => {
                write!(f, "process timed out after {runtime_millis}ms")
            }
            Self::Io { operation, detail } => {
                write!(f, "process I/O error during {operation}: {detail}")
            }
            Self::ReplayDivergence {
                index,
                live_kind,
                recorded_kind,
            } => write!(
                f,
                "process replay divergence at index {index}: live {live_kind} != recorded {recorded_kind}"
            ),
        }
    }
}

impl std::error::Error for ProcessSpawnError {}

pub type ProcessSpawnOutcome = Result<ProcessSpawnResponse, ProcessSpawnError>;

/// Resource ceilings applied to every native provider instance.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProcessSpawnLimits {
    pub max_children: u64,
    pub max_argv_count: u64,
    pub max_argv_bytes: u64,
    pub max_stdin_bytes: u64,
    /// Per-stream capture cap.
    pub max_output_bytes: u64,
    pub max_runtime_millis: u64,
}

impl Default for ProcessSpawnLimits {
    fn default() -> Self {
        Self {
            max_children: 4,
            max_argv_count: 128,
            max_argv_bytes: 64 * 1024,
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
/// immediately before launch. An empty map denies every executable.
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
            .field("allowed_executables", &self.allowed_executables)
            .field("executable_aliases", &self.executable_aliases)
            .field("allow_shell", &self.allow_shell)
            .field("shell_executable_alias", &self.shell_executable_alias)
            .field("allowed_env_keys", &self.allowed_env_keys)
            .field("fixed_env_keys", &self.fixed_env.keys().collect::<Vec<_>>())
            .field("jailed_cwd_root", &self.jailed_cwd_root)
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
            allowed_signals: BTreeSet::from([ProcessSignal::Kill]),
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
    /// The provider re-hashes the file before every launch; this method does not
    /// turn the setup-time digest into a trust-on-first-use bypass.
    pub fn authorize_executable(
        &mut self,
        executable: impl AsRef<Path>,
    ) -> Result<String, ProcessSpawnError> {
        let canonical =
            std::fs::canonicalize(executable.as_ref()).map_err(|error| ProcessSpawnError::Io {
                operation: "canonicalize executable".to_string(),
                detail: error.to_string(),
            })?;
        if !canonical.is_file() {
            return Err(ProcessSpawnError::PolicyViolation {
                code: "executable_not_file".to_string(),
                detail: canonical.display().to_string(),
            });
        }
        let canonical = path_string(&canonical)?;
        let digest = digest_file(Path::new(&canonical))?;
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

    /// Abandon one engine-owned lifecycle handle during execution teardown.
    /// This is compensating containment, not a guest-requested signal: native
    /// providers must synchronously revoke ownership and reap any live child
    /// even when the signed guest policy does not grant `Kill`.
    fn cleanup_handle(&self, handle: &str);
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

    fn cleanup_handle(&self, _handle: &str) {}
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

#[derive(Debug)]
struct CapturedOutput {
    bytes: Vec<u8>,
    overflowed: bool,
    maximum: u64,
}

#[derive(Debug)]
struct OutputDrain {
    cancel: Arc<AtomicBool>,
    thread: JoinHandle<std::io::Result<CapturedOutput>>,
}

#[derive(Debug)]
struct RunningChild {
    child: Child,
    stdin: Option<ChildStdin>,
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
        #[cfg(not(unix))]
        {
            let _ = policy;
            Err(ProcessSpawnError::NotImplemented {
                what: "native process containment requires a platform job/process-group backend"
                    .to_string(),
            })
        }
        #[cfg(unix)]
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

    fn validate_launch(
        &self,
        launch: &ProcessLaunch,
    ) -> Result<ValidatedLaunch, ProcessSpawnError> {
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
            std::fs::canonicalize(&launch.executable).map_err(|error| ProcessSpawnError::Io {
                operation: "canonicalize executable".to_string(),
                detail: error.to_string(),
            })?;
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
        let actual_digest = digest_file(&executable)?;
        if &actual_digest != expected_digest {
            return Err(policy_error(
                "executable_digest_mismatch",
                format!("digest changed for {executable_string}"),
            ));
        }

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

        Ok(ValidatedLaunch {
            executable,
            argv: launch.argv.clone(),
            env,
            cwd,
            stdio: launch.stdio,
        })
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
            // Preparation is idempotent because `perform_recorded` prepares
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
        Ok(match request {
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
        })
    }

    fn spawn_validated(
        &self,
        launch: ValidatedLaunch,
        permit: ActiveChildPermit,
    ) -> Result<RunningChild, ProcessSpawnError> {
        let mut command = Command::new(&launch.executable);
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
        let mut child = command.spawn().map_err(|error| ProcessSpawnError::Io {
            operation: "spawn".to_string(),
            detail: error.to_string(),
        })?;
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

    fn launch(&self, launch: &ProcessLaunch) -> Result<RunningChild, ProcessSpawnError> {
        let launch = self.validate_launch(launch)?;
        let permit = self.reserve_child()?;
        self.spawn_validated(launch, permit)
    }

    fn run(
        &self,
        launch: &ProcessLaunch,
        stdin: &[u8],
        timeout_millis: Option<u64>,
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
        let mut running = self.launch(launch)?;
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
        let process_result = wait_and_collect(running, timeout);
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

    fn spawn(&self, launch: &ProcessLaunch) -> ProcessSpawnOutcome {
        let running = self.launch(launch)?;
        let nonce = self.next_handle.fetch_add(1, Ordering::Relaxed);
        let handle = format!("ps-{}-{nonce:016x}", self.scope);
        lock_unpoison(&self.children).insert(handle.clone(), LifecycleChild::Running(running));
        match self.start_watchdog(handle.clone()) {
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
                    let _ = collect_outputs(running);
                }
                return Err(error);
            }
        }
        Ok(ProcessSpawnResponse::Spawned { handle })
    }

    fn start_watchdog(&self, handle: String) -> Result<SyncSender<()>, ProcessSpawnError> {
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
                if cancelled.recv_timeout(timeout).is_ok() {
                    return;
                }
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
                    Ok(Some(status)) => collect_outputs(running).map(|(stdout, stderr)| {
                        ProcessSpawnResponse::Waited {
                            exit: exit_from_status(status),
                            stdout,
                            stderr,
                        }
                    }),
                    Ok(None) => {
                        let _ = terminate_remaining_process_group(&running);
                        kill_and_reap(&mut running.child);
                        let runtime_millis = elapsed_millis(running.started);
                        let _ = collect_outputs(running);
                        Err(ProcessSpawnError::TimedOut { runtime_millis })
                    }
                    Err(error) => {
                        let _ = terminate_remaining_process_group(&running);
                        kill_and_reap(&mut running.child);
                        let _ = collect_outputs(running);
                        Err(ProcessSpawnError::Io {
                            operation: "watchdog poll child".to_string(),
                            detail: error.to_string(),
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
        if requested != 0 {
            return Err(ProcessSpawnError::NotImplemented {
                what: "non-empty lifecycle stdin writes require bounded backpressure".to_string(),
            });
        }
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
            kill_and_reap(&mut running.child);
            let elapsed = elapsed_millis(running.started);
            let _ = collect_outputs(running);
            return Err(ProcessSpawnError::TimedOut {
                runtime_millis: elapsed,
            });
        }
        let total = running.stdin_written.saturating_add(requested);
        enforce_limit("stdin_bytes", total, self.policy.limits.max_stdin_bytes)?;
        if running.stdin.is_none() {
            return Err(ProcessSpawnError::InvalidState {
                detail: format!("stdin is not writable for handle {handle}"),
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
        if running.stdin.take().is_none() {
            return Err(ProcessSpawnError::InvalidState {
                detail: format!("stdin is already closed or was not piped for handle {handle}"),
            });
        }
        Ok(ProcessSpawnResponse::StdinClosed)
    }

    fn wait(&self, handle: &str, timeout_millis: Option<u64>) -> ProcessSpawnOutcome {
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
        let (exit, stdout, stderr) = wait_and_collect(running, timeout)?;
        Ok(ProcessSpawnResponse::Waited {
            exit,
            stdout,
            stderr,
        })
    }

    fn kill(&self, handle: &str, signal: ProcessSignal) -> ProcessSpawnOutcome {
        if !self.policy.allowed_signals.contains(&signal) {
            return Err(policy_error(
                "signal_denied",
                format!("signal {} is not allowed", signal.as_str()),
            ));
        }
        if signal != ProcessSignal::Kill {
            return Err(ProcessSpawnError::NotImplemented {
                what: format!(
                    "signal {} requires a platform signal API not available in std",
                    signal.as_str()
                ),
            });
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
            let group_result = terminate_remaining_process_group(&running);
            let child_result = running.child.kill();
            if let (Err(group_error), Err(child_error)) = (group_result, child_result) {
                // A process may exit between `try_wait` and signalling. Always
                // reap before reporting the failed containment attempt.
                let _ = running.child.wait();
                let _ = collect_outputs(running);
                return Err(ProcessSpawnError::Io {
                    operation: "kill process group and child".to_string(),
                    detail: format!("{group_error}; direct child fallback: {child_error}"),
                });
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
        let (stdout, stderr) = collect_outputs(running)?;
        Ok(ProcessSpawnResponse::Killed {
            signal,
            exit: exit_from_status(status),
            stdout,
            stderr,
        })
    }
}

impl ProcessSpawnProvider for NativeProcessSpawn {
    fn name(&self) -> &str {
        "native-process-spawn"
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
        let required = request.required_capability();
        if !process_capability_granted(granted, required) {
            return Err(ProcessSpawnError::CapabilityMissing {
                capability: required,
            });
        }
        let request = self.prepare_process_request(request)?;
        match &request {
            ProcessSpawnRequest::Run {
                launch,
                stdin,
                timeout_millis,
            } => self.run(launch, stdin, *timeout_millis),
            ProcessSpawnRequest::Spawn { launch } => self.spawn(launch),
            ProcessSpawnRequest::WriteStdin { handle, data } => self.write_stdin(handle, data),
            ProcessSpawnRequest::CloseStdin { handle } => self.close_stdin(handle),
            ProcessSpawnRequest::Wait {
                handle,
                timeout_millis,
            } => self.wait(handle, *timeout_millis),
            ProcessSpawnRequest::Kill { handle, signal } => self.kill(handle, *signal),
        }
    }

    fn cleanup_handle(&self, handle: &str) {
        let state = lock_unpoison(&self.children).remove(handle);
        if let Some(LifecycleChild::Running(mut running)) = state {
            cancel_watchdog(&mut running);
            let _ = terminate_remaining_process_group(&running);
            kill_and_reap(&mut running.child);
            let _ = collect_outputs(running);
        }
    }
}

impl Drop for NativeProcessSpawn {
    fn drop(&mut self) {
        let children = {
            let mut children = lock_unpoison(&self.children);
            std::mem::take(&mut *children)
        };
        for (_, state) in children {
            if let LifecycleChild::Running(mut running) = state {
                cancel_watchdog(&mut running);
                let _ = terminate_remaining_process_group(&running);
                kill_and_reap(&mut running.child);
                let _ = collect_outputs(running);
            }
        }
    }
}

#[derive(Debug)]
struct ValidatedLaunch {
    executable: PathBuf,
    argv: Vec<String>,
    env: BTreeMap<String, String>,
    cwd: PathBuf,
    stdio: ProcessStdio,
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
    for (key, value) in &policy.fixed_env {
        validate_env_pair(key, value)?;
    }
    for executable in policy.allowed_executables.keys() {
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

fn digest_file(path: &Path) -> Result<[u8; 32], ProcessSpawnError> {
    let mut file = File::open(path).map_err(|error| ProcessSpawnError::Io {
        operation: "open executable for digest".to_string(),
        detail: error.to_string(),
    })?;
    let mut digest = Sha256::new();
    let mut buffer = [0_u8; 16 * 1024];
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
        digest.update(&buffer[..read]);
    }
    Ok(digest.finalize().into())
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
    cancel_watchdog(&mut running);
    // A child may exit after spawning a descendant that inherited its pipes.
    // Give ordinary buffered output a short grace period, then terminate the
    // child's private process group before joining. Nonblocking reader threads
    // have their own cancellation flag as the final bound, so even a
    // session-escaping descendant cannot hold engine teardown forever.
    wait_for_output_drains(&running, Duration::from_millis(50));
    let group_teardown = if !output_drains_finished(&running) {
        let result = terminate_remaining_process_group(&running);
        wait_for_output_drains(&running, Duration::from_millis(250));
        result
    } else {
        Ok(())
    };
    let stdout = join_reader(running.stdout, "stdout");
    let stderr = join_reader(running.stderr, "stderr");
    group_teardown?;
    let stdout = stdout?;
    let stderr = stderr?;
    if stdout.overflowed {
        return Err(ProcessSpawnError::LimitExceeded {
            limit: "stdout_bytes".to_string(),
            actual: stdout.maximum.saturating_add(1),
            maximum: stdout.maximum,
        });
    }
    if stderr.overflowed {
        return Err(ProcessSpawnError::LimitExceeded {
            limit: "stderr_bytes".to_string(),
            actual: stderr.maximum.saturating_add(1),
            maximum: stderr.maximum,
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

fn wait_for_output_drains(running: &RunningChild, timeout: Duration) {
    let deadline = Instant::now().checked_add(timeout);
    while !output_drains_finished(running)
        && deadline.is_some_and(|deadline| Instant::now() < deadline)
    {
        thread::sleep(Duration::from_millis(2));
    }
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

fn wait_and_collect(
    mut running: RunningChild,
    timeout: Duration,
) -> Result<(ProcessExit, Vec<u8>, Vec<u8>), ProcessSpawnError> {
    let deadline = Instant::now().checked_add(timeout);
    let status = loop {
        match running.child.try_wait() {
            Err(error) => {
                let _ = terminate_remaining_process_group(&running);
                kill_and_reap(&mut running.child);
                let _ = collect_outputs(running);
                return Err(ProcessSpawnError::Io {
                    operation: "poll child".to_string(),
                    detail: error.to_string(),
                });
            }
            Ok(Some(status)) => break status,
            Ok(None) => {}
        }
        if deadline.is_none_or(|deadline| Instant::now() >= deadline) {
            let _ = terminate_remaining_process_group(&running);
            kill_and_reap(&mut running.child);
            let elapsed = elapsed_millis(running.started);
            let _ = collect_outputs(running);
            return Err(ProcessSpawnError::TimedOut {
                runtime_millis: elapsed,
            });
        }
        thread::sleep(Duration::from_millis(2));
    };
    let exit = exit_from_status(status);
    let (stdout, stderr) = collect_outputs(running)?;
    Ok((exit, stdout, stderr))
}

fn kill_and_reap(child: &mut Child) {
    match child.try_wait() {
        Ok(Some(_)) => {}
        Ok(None) | Err(_) => {
            let _ = child.kill();
            let _ = child.wait();
        }
    }
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

/// Execute through a transcript: replay never reaches the live provider.
pub fn perform_recorded(
    provider: &dyn ProcessSpawnProvider,
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
    let prepared = match provider.prepare_request(request) {
        Ok(prepared) => prepared,
        Err(error) => {
            if let Some(outcome) = recorder.and_then(|recorder| recorder.replay(request)) {
                return outcome;
            }
            let outcome = Err(error);
            if let Some(recorder) = recorder {
                recorder.record(request, &outcome);
            }
            return outcome;
        }
    };
    if let Some(outcome) = recorder.and_then(|recorder| recorder.replay(&prepared)) {
        return outcome;
    }
    let outcome = provider.perform(&prepared, granted);
    if let Some(recorder) = recorder {
        recorder.record(&prepared, &outcome);
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
        policy.limits.max_runtime_millis = 2_000;
        (
            NativeProcessSpawn::new(policy).expect("native provider"),
            canonical,
        )
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
    fn policy_and_provider_debug_redact_fixed_environment_values() {
        let echo = executable(&["/bin/echo", "/usr/bin/echo"]);
        let mut policy = ProcessSpawnPolicy::jailed("/").expect("rooted policy");
        policy.authorize_executable(&echo).expect("authorize echo");
        policy.fixed_env.insert(
            "API_TOKEN".to_string(),
            "never-print-this-secret".to_string(),
        );
        let policy_debug = format!("{policy:?}");
        assert!(policy_debug.contains("API_TOKEN"));
        assert!(!policy_debug.contains("never-print-this-secret"));

        let provider = NativeProcessSpawn::new(policy).expect("native provider");
        let provider_debug = format!("{provider:?}");
        assert!(provider_debug.contains("API_TOKEN"));
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

    #[cfg(unix)]
    #[test]
    fn signed_alias_is_resolved_before_recording_or_dispatch() {
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
            Ok(ProcessSpawnResponse::Run { ref stdout, .. }) if stdout == b"aliased\n"
        ));
        let current = recorder.finish_execution().expect("finish recording");
        let ProcessSpawnRequest::Run { launch, .. } = &current[0].0 else {
            panic!("run transcript");
        };
        assert_eq!(launch.executable, canonical);
        assert_ne!(launch.executable, "echo");

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
            Err(ProcessSpawnError::LimitExceeded {
                ref limit,
                maximum: 4,
                ..
            }) if limit == "stdout_bytes"
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
            Err(ProcessSpawnError::TimedOut { .. })
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
            Err(ProcessSpawnError::TimedOut { .. })
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
        *stdin = vec![b'x'; 512 * 1024];
        *timeout_millis = Some(10);
        let started = Instant::now();
        assert!(matches!(
            provider.perform(&request, &[ProcessSpawnCapability::Spawn]),
            Err(ProcessSpawnError::TimedOut { .. })
        ));
        assert!(started.elapsed() < Duration::from_secs(2));
        assert_eq!(provider.active_children.load(Ordering::Acquire), 0);
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
            Err(ProcessSpawnError::NotImplemented { .. })
        ));
        assert!(handle.starts_with("ps-"));
        assert!(!handle.contains(&std::process::id().to_string()));
        assert!(matches!(
            provider.perform(
                &ProcessSpawnRequest::Kill {
                    handle: handle.clone(),
                    signal: ProcessSignal::Kill,
                },
                &[ProcessSpawnCapability::Spawn],
            ),
            Ok(ProcessSpawnResponse::Killed { .. })
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

        provider.cleanup_handle(&handle);

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
            recorded,
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
            mismatch,
            ProcessSpawnError::ReplayDivergence { .. }
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
