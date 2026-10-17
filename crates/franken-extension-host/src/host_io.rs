//! Sandboxed guest I/O surface for the extension host.
//!
//! The engine must not perform guest filesystem or network I/O directly. It
//! routes capability-checked requests to a host-side [`HostIoProvider`]. The
//! default provider denies every request, preserving fail-closed behavior until
//! a real sandboxed provider is deliberately installed.

use serde::{Deserialize, Serialize};
#[cfg(unix)]
use std::ffi::{OsStr, OsString};
use std::io::{Read, Write};
use std::net::Shutdown;
#[cfg(unix)]
use std::os::fd::OwnedFd;
use std::path::{Component, Path, PathBuf};
use std::time::Duration;

#[path = "host_io_budget.rs"]
pub mod budget;
mod control;
mod fd_write;
#[cfg(all(test, unix))]
mod fd_admission_tests;
mod http_response;
mod network_deadline;
pub use control::{HostIoControl, UnrestrictedHostIoControl};
pub use http_response::{ParsedHttpResponse, parse_http_response};
pub use network_deadline::NetworkRevocation;
use network_deadline::{DeadlineTcpStream, NetworkDeadline};

/// Capability a guest must hold for the host to perform a given I/O request.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum HostIoCapability {
    FsRead,
    FsWrite,
    NetworkSend,
    NetworkRecv,
    /// Read fresh bytes from the host operating-system CSPRNG.
    RandomRead,
    /// Read one explicitly supplied environment variable.
    EnvRead,
}

/// Filesystem operation carried across the engine/host policy seam.
///
/// Read-class operations deliberately reuse [`HostIoCapability::FsRead`] and
/// mutation-class operations reuse [`HostIoCapability::FsWrite`].  The
/// operation remains a separate, transcripted field so receipts commit to the
/// concrete action without proliferating capability tags.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FsOperation {
    Read,
    Write,
    Append,
    Exists,
    Mkdir,
    ReadDir,
    Stat,
    Lstat,
    Symlink,
    ReadLink,
    Rename,
    CopyFile,
    Unlink,
    Remove,
    RemoveDir,
    Truncate,
    Access,
    Chmod,
    Utimes,
    Realpath,
    Mkdtemp,
    /// `fs.openSync(path, flags)` — open a numeric fd in the sandbox fd table
    /// (bd-zco6t). Conservatively classified as write authority because an
    /// open can create or truncate depending on its flags.
    Open,
    /// `fs.writeSync(fd, data)` — write through an open fd (bd-zco6t).
    WriteFd,
    /// `fs.readSync(fd, ..., position)` — read through an open fd, positional
    /// reads leaving the cursor untouched (bd-zco6t).
    ReadFd,
    /// `fs.fsyncSync(fd)` (bd-zco6t).
    Fsync,
    /// `fs.closeSync(fd)` (bd-zco6t).
    CloseFd,
}

impl FsOperation {
    #[must_use]
    pub const fn required_capability(self) -> HostIoCapability {
        match self {
            Self::Read
            | Self::Exists
            | Self::ReadDir
            | Self::Stat
            | Self::Lstat
            | Self::ReadLink
            | Self::Access
            | Self::ReadFd
            | Self::Realpath => HostIoCapability::FsRead,
            Self::Write
            | Self::Append
            | Self::Mkdir
            | Self::Symlink
            | Self::Rename
            | Self::CopyFile
            | Self::Unlink
            | Self::Remove
            | Self::RemoveDir
            | Self::Truncate
            | Self::Chmod
            | Self::Utimes
            | Self::Mkdtemp
            | Self::Open
            | Self::WriteFd
            | Self::Fsync
            | Self::CloseFd => HostIoCapability::FsWrite,
        }
    }

    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Read => "read",
            Self::Write => "write",
            Self::Append => "append",
            Self::Exists => "exists",
            Self::Mkdir => "mkdir",
            Self::ReadDir => "readdir",
            Self::Stat => "stat",
            Self::Lstat => "lstat",
            Self::Symlink => "symlink",
            Self::ReadLink => "readlink",
            Self::Rename => "rename",
            Self::CopyFile => "copy_file",
            Self::Unlink => "unlink",
            Self::Remove => "remove",
            Self::RemoveDir => "rmdir",
            Self::Truncate => "truncate",
            Self::Access => "access",
            Self::Chmod => "chmod",
            Self::Utimes => "utimes",
            Self::Realpath => "realpath",
            Self::Mkdtemp => "mkdtemp",
            Self::Open => "open",
            Self::WriteFd => "write_fd",
            Self::ReadFd => "read_fd",
            Self::Fsync => "fsync",
            Self::CloseFd => "close_fd",
        }
    }

    #[must_use]
    pub fn parse_name(value: &str) -> Option<Self> {
        Some(match value {
            "read" => Self::Read,
            "write" => Self::Write,
            "append" => Self::Append,
            "exists" => Self::Exists,
            "mkdir" => Self::Mkdir,
            "readdir" => Self::ReadDir,
            "stat" => Self::Stat,
            "lstat" => Self::Lstat,
            "symlink" => Self::Symlink,
            "readlink" => Self::ReadLink,
            "rename" => Self::Rename,
            "copy_file" => Self::CopyFile,
            "unlink" => Self::Unlink,
            "remove" => Self::Remove,
            "rmdir" => Self::RemoveDir,
            "truncate" => Self::Truncate,
            "access" => Self::Access,
            "chmod" => Self::Chmod,
            "utimes" => Self::Utimes,
            "realpath" => Self::Realpath,
            "mkdtemp" => Self::Mkdtemp,
            "open" => Self::Open,
            "write_fd" => Self::WriteFd,
            "read_fd" => Self::ReadFd,
            "fsync" => Self::Fsync,
            "close_fd" => Self::CloseFd,
            _ => return None,
        })
    }
}

/// Stable, platform-neutral subset of Node's `fs.Stats` surface.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FsMetadata {
    pub size: u64,
    pub mode: u32,
    pub modified_millis: i64,
    pub is_file: bool,
    pub is_directory: bool,
    pub is_symbolic_link: bool,
}

/// Stable subset of a Node `Dirent` returned by `readdir({withFileTypes:true})`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FsDirEntry {
    pub name: String,
    pub is_file: bool,
    pub is_directory: bool,
    pub is_symbolic_link: bool,
}

/// Typed result for non-streaming filesystem operations.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", tag = "kind", content = "value")]
pub enum FsMetaResult {
    Unit,
    Bool(bool),
    Unsigned(u64),
    String(String),
    Strings(Vec<String>),
    DirEntries(Vec<FsDirEntry>),
    Metadata(FsMetadata),
    /// Raw binary bytes (fd-based `read_fd` results, bd-zco6t). A dedicated
    /// variant so 0x80..=0xFF bytes never round-trip through a lossy string.
    Bytes(Vec<u8>),
}

impl HostIoCapability {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::FsRead => "fs_read",
            Self::FsWrite => "fs_write",
            Self::NetworkSend => "network_send",
            Self::NetworkRecv => "network_recv",
            Self::RandomRead => "random_read",
            Self::EnvRead => "env_read",
        }
    }
}

/// A guest I/O request the engine asks the host to perform on the guest's behalf.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", tag = "kind")]
pub enum HostIoRequest {
    FsRead {
        path: String,
    },
    FsWrite {
        path: String,
        data: Vec<u8>,
    },
    /// Non-streaming filesystem operation beyond the read/write keystone.
    /// `arguments` are operation-specific canonical strings (second path,
    /// boolean options, lengths/modes/timestamps); `data` is populated only for
    /// byte-consuming operations such as append.
    FsMeta {
        operation: FsOperation,
        path: String,
        arguments: Vec<String>,
        data: Vec<u8>,
    },
    NetworkSend {
        endpoint: String,
        payload: Vec<u8>,
    },
    NetworkRecv {
        endpoint: String,
        max_len: u64,
    },
    /// A single-socket request/response round trip: connect to `endpoint`, write
    /// `payload` (the framed request), then read the reply back on the *same*
    /// socket bounded by `max_len`. `NetworkSend` (egress-only) and `NetworkRecv`
    /// (a fresh socket) cannot carry an HTTP request/response pair across one
    /// connection; `NetworkRequest` is the shape a `http.get`/`fetch` needs so the
    /// guest can observe the real response (status/headers/body). The egress is
    /// the security-relevant action, so it carries `HostIoCapability::NetworkSend`
    /// and is gated by the product-layer SSRF policy exactly like `NetworkSend`.
    ///
    /// bd-3894s slice (5): `use_tls` marks a round trip whose guest URL carried an
    /// `https://` scheme — the mechanism wraps the TCP stream in a real TLS
    /// session (SNI from the endpoint host, roots = webpki + any operator-supplied
    /// extras) before writing the framed request. `#[serde(default)]` keeps
    /// previously-recorded plaintext transcripts deserializable (`false`).
    NetworkRequest {
        endpoint: String,
        payload: Vec<u8>,
        max_len: u64,
        #[serde(default)]
        use_tls: bool,
    },
    /// Request fresh cryptographic entropy. The request records only the exact
    /// byte count; the outcome carries the bytes so replay can return them
    /// without consulting a live entropy source.
    RandomRead {
        byte_len: u64,
    },
    /// Read one name from the host's explicitly supplied environment snapshot.
    /// The host process environment is never consulted implicitly.
    EnvRead {
        name: String,
    },
}

impl HostIoRequest {
    /// Whether this request crosses the host network boundary.
    #[must_use]
    pub const fn is_network(&self) -> bool {
        matches!(
            self,
            Self::NetworkSend { .. } | Self::NetworkRecv { .. } | Self::NetworkRequest { .. }
        )
    }

    #[must_use]
    pub const fn required_capability(&self) -> HostIoCapability {
        match self {
            Self::FsRead { .. } => HostIoCapability::FsRead,
            Self::FsWrite { .. } => HostIoCapability::FsWrite,
            Self::FsMeta { operation, .. } => operation.required_capability(),
            Self::NetworkSend { .. } => HostIoCapability::NetworkSend,
            Self::NetworkRecv { .. } => HostIoCapability::NetworkRecv,
            // The egress write is the gated action; reading the reply on the same
            // socket is its natural completion, not a separately-grantable read.
            Self::NetworkRequest { .. } => HostIoCapability::NetworkSend,
            Self::RandomRead { .. } => HostIoCapability::RandomRead,
            Self::EnvRead { .. } => HostIoCapability::EnvRead,
        }
    }

    #[must_use]
    pub const fn kind(&self) -> &'static str {
        match self {
            Self::FsRead { .. } => "fs_read",
            Self::FsWrite { .. } => "fs_write",
            Self::FsMeta { .. } => "fs_meta",
            Self::NetworkSend { .. } => "network_send",
            Self::NetworkRecv { .. } => "network_recv",
            Self::NetworkRequest { .. } => "network_request",
            Self::RandomRead { .. } => "random_read",
            Self::EnvRead { .. } => "env_read",
        }
    }
}

/// Successful result of a host I/O request.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", tag = "kind")]
pub enum HostIoResponse {
    FsRead {
        bytes: Vec<u8>,
    },
    FsWrite {
        bytes_written: u64,
    },
    FsMeta {
        result: FsMetaResult,
    },
    NetworkSend {
        bytes_sent: u64,
    },
    NetworkRecv {
        bytes: Vec<u8>,
    },
    /// Raw response bytes read back on the same socket by a [`HostIoRequest::NetworkRequest`]
    /// round trip (status line + headers + body, exactly as the peer sent them).
    NetworkRequest {
        response: Vec<u8>,
    },
    /// Fresh bytes returned by the operating-system CSPRNG, or the exact bytes
    /// supplied by a replay transcript.
    RandomRead {
        bytes: Vec<u8>,
    },
    /// `None` is an absent name; `Some("")` is a present, empty value.
    /// This outcome is recorded for replay and carries a Secret IFC floor.
    EnvRead {
        value: Option<String>,
    },
}

/// Failure result of a host I/O request.
///
/// Every variant is fail-closed: a host that cannot positively authorize and
/// perform a request must return an error, never a partial or faked success.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", tag = "kind")]
pub enum HostIoError {
    Denied {
        reason: String,
    },
    CapabilityMissing {
        capability: HostIoCapability,
    },
    NotImplemented {
        what: String,
    },
    SandboxViolation {
        detail: String,
    },
    /// Guest-visible filesystem failure with a stable Node-style error code.
    /// Policy/capability/sandbox failures remain separate non-catchable variants.
    Fs {
        code: String,
        detail: String,
    },
    Io {
        detail: String,
    },
}

impl core::fmt::Display for HostIoError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Denied { reason } => write!(f, "host I/O denied: {reason}"),
            Self::CapabilityMissing { capability } => {
                write!(f, "host I/O capability missing: {}", capability.as_str())
            }
            Self::NotImplemented { what } => write!(f, "host I/O not implemented: {what}"),
            Self::SandboxViolation { detail } => write!(f, "host I/O sandbox violation: {detail}"),
            Self::Fs { code, detail } => write!(f, "host filesystem error {code}: {detail}"),
            Self::Io { detail } => write!(f, "host I/O error: {detail}"),
        }
    }
}

impl std::error::Error for HostIoError {}

pub type HostIoOutcome = Result<HostIoResponse, HostIoError>;

/// Provenance floor for guest-visible exceptions raised by a host-I/O effect
/// source (the live provider or a replay source).
///
/// This is an authenticated host contract, not a label inferred from provider
/// names. [`ProviderInternal`](Self::ProviderInternal) means filesystem errors
/// depend only on the typed request and provider-internal sandbox state. The
/// fail-closed default is [`Unknown`](Self::Unknown), which callers must treat
/// as potentially carrying arbitrary secret state.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum HostIoExceptionProvenance {
    #[default]
    Unknown,
    ProviderInternal,
}

impl HostIoExceptionProvenance {
    /// Combine every source that may supply a host-I/O outcome. A bounded live
    /// provider is insufficient when an untrusted recorder or journal can
    /// replace that outcome during replay, so any unknown source wins.
    #[must_use]
    pub const fn combine(self, other: Self) -> Self {
        match (self, other) {
            (Self::ProviderInternal, Self::ProviderInternal) => Self::ProviderInternal,
            (Self::Unknown, _) | (_, Self::Unknown) => Self::Unknown,
        }
    }
}

/// A sandboxed host I/O provider.
pub trait HostIoProvider: core::fmt::Debug + Send + Sync {
    fn name(&self) -> &str;

    /// Declare the provenance floor for guest-visible filesystem exceptions.
    /// Decorators must delegate this method to their wrapped provider. Custom
    /// providers remain fail-high unless they deliberately implement the same
    /// bounded exception contract as [`SandboxedHostIo`].
    fn filesystem_exception_provenance(&self) -> HostIoExceptionProvenance {
        HostIoExceptionProvenance::Unknown
    }

    /// Perform `request` using only the capabilities explicitly granted.
    ///
    /// Implementations must verify [`HostIoRequest::required_capability`] is
    /// present in `granted` before doing I/O and must fail closed otherwise.
    fn perform(&self, request: &HostIoRequest, granted: &[HostIoCapability]) -> HostIoOutcome;

    /// Execute with a live, operation-local supervisor control. Network
    /// providers must override this and poll during DNS, connect, TLS and I/O;
    /// a boundary-only check cannot interrupt an already blocked operation.
    /// Decorators must forward the control, not call the wrapped `perform`.
    /// The default refuses network dispatch rather than silently dropping the
    /// control. Non-network requests retain their existing synchronous contract.
    fn perform_controlled(
        &self,
        request: &HostIoRequest,
        granted: &[HostIoCapability],
        control: std::sync::Arc<dyn HostIoControl>,
    ) -> HostIoOutcome {
        control::OperationControl::new(control).check_host()?;
        if request.is_network() {
            return Err(HostIoError::NotImplemented {
                what: "provider does not implement controlled network execution".to_string(),
            });
        }
        self.perform(request, granted)
    }
}

/// Default provider: denies every request.
#[derive(Debug, Clone, Copy, Default)]
pub struct DenyAllHostIo;

impl HostIoProvider for DenyAllHostIo {
    fn name(&self) -> &str {
        "deny-all-host-io"
    }

    fn perform(&self, _request: &HostIoRequest, _granted: &[HostIoCapability]) -> HostIoOutcome {
        Err(HostIoError::Denied {
            reason: "no sandboxed host I/O provider installed; fail-closed deny".to_string(),
        })
    }

    fn perform_controlled(
        &self,
        request: &HostIoRequest,
        granted: &[HostIoCapability],
        control: std::sync::Arc<dyn HostIoControl>,
    ) -> HostIoOutcome {
        control::OperationControl::new(control).check_host()?;
        self.perform(request, granted)
    }
}

/// Hard bounds on explicitly supplied environment authority. The snapshot is
/// immutable, and only requested values enter the ordinary host-effect journal.
pub const ENVIRONMENT_SNAPSHOT_MAX_ENTRIES: usize = 4096;
pub const ENVIRONMENT_NAME_MAX_BYTES: usize = 4096;
pub const ENVIRONMENT_VALUE_MAX_BYTES: usize = 64 * 1024;
pub const ENVIRONMENT_SNAPSHOT_MAX_BYTES: usize = 1024 * 1024;

/// Host-owned environment snapshot composed with an existing I/O provider.
///
/// Construction is the explicit allowlist: names omitted from `values` are
/// absent to the guest even when they exist in the host process environment.
/// There is no ambient `std::env` fallback. All reads still require EnvRead,
/// and other requests retain the wrapped provider's policy and supervision.
#[derive(Clone)]
pub struct EnvironmentSnapshotHostIo {
    values: std::collections::BTreeMap<String, String>,
    inner: std::sync::Arc<dyn HostIoProvider>,
}

impl core::fmt::Debug for EnvironmentSnapshotHostIo {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("EnvironmentSnapshotHostIo")
            .field("entry_count", &self.values.len())
            .field("values", &"[redacted]")
            .finish_non_exhaustive()
    }
}

impl EnvironmentSnapshotHostIo {
    /// Supply a bounded snapshot while denying every other host-I/O family.
    pub fn new(values: std::collections::BTreeMap<String, String>) -> Result<Self, HostIoError> {
        Self::with_provider(values, std::sync::Arc::new(DenyAllHostIo))
    }

    /// Compose explicit environment authority with the existing host provider.
    pub fn with_provider(
        values: std::collections::BTreeMap<String, String>,
        inner: std::sync::Arc<dyn HostIoProvider>,
    ) -> Result<Self, HostIoError> {
        if values.len() > ENVIRONMENT_SNAPSHOT_MAX_ENTRIES {
            return Err(HostIoError::SandboxViolation {
                detail: "environment snapshot exceeds the entry limit".to_string(),
            });
        }
        let mut total_bytes = 0usize;
        for (name, value) in &values {
            validate_environment_name(name)?;
            if name.is_empty() || value.len() > ENVIRONMENT_VALUE_MAX_BYTES || value.contains('\0')
            {
                return Err(HostIoError::SandboxViolation {
                    detail: "environment snapshot contains an invalid or oversized entry"
                        .to_string(),
                });
            }
            total_bytes = total_bytes
                .checked_add(name.len())
                .and_then(|bytes| bytes.checked_add(value.len()))
                .filter(|bytes| *bytes <= ENVIRONMENT_SNAPSHOT_MAX_BYTES)
                .ok_or_else(|| HostIoError::SandboxViolation {
                    detail: "environment snapshot exceeds the aggregate byte limit".to_string(),
                })?;
        }
        Ok(Self { values, inner })
    }

    fn read(&self, name: &str, granted: &[HostIoCapability]) -> HostIoOutcome {
        if !capability_granted(granted, HostIoCapability::EnvRead) {
            return Err(HostIoError::CapabilityMissing {
                capability: HostIoCapability::EnvRead,
            });
        }
        validate_environment_name(name)?;
        Ok(HostIoResponse::EnvRead {
            value: self.values.get(name).cloned(),
        })
    }
}

/// Validate request shape before it is cloned, journaled or dispatched.
pub fn validate_environment_name(name: &str) -> Result<(), HostIoError> {
    if name.len() > ENVIRONMENT_NAME_MAX_BYTES || name.contains(['\0', '=']) {
        return Err(HostIoError::SandboxViolation {
            detail: "environment variable name is invalid or exceeds the byte limit".to_string(),
        });
    }
    Ok(())
}

impl HostIoProvider for EnvironmentSnapshotHostIo {
    fn name(&self) -> &str {
        "environment-snapshot-host-io"
    }

    fn filesystem_exception_provenance(&self) -> HostIoExceptionProvenance {
        self.inner.filesystem_exception_provenance()
    }

    fn perform(&self, request: &HostIoRequest, granted: &[HostIoCapability]) -> HostIoOutcome {
        match request {
            HostIoRequest::EnvRead { name } => self.read(name, granted),
            _ => self.inner.perform(request, granted),
        }
    }

    fn perform_controlled(
        &self,
        request: &HostIoRequest,
        granted: &[HostIoCapability],
        control: std::sync::Arc<dyn HostIoControl>,
    ) -> HostIoOutcome {
        if let HostIoRequest::EnvRead { name } = request {
            control::OperationControl::new(control).check_host()?;
            self.read(name, granted)
        } else {
            self.inner.perform_controlled(request, granted, control)
        }
    }
}

#[must_use]
pub fn capability_granted(granted: &[HostIoCapability], required: HostIoCapability) -> bool {
    granted.contains(&required)
}

/// Default per-operation byte cap for [`SandboxedHostIo`] (16 MiB). Bounds memory
/// use and provides a parser-bomb / OOM defense; mirrors the franken_node CAS
/// per-blob cap.
pub const SANDBOXED_HOST_IO_MAX_BYTES: u64 = 16 * 1024 * 1024;

/// Maximum simultaneously retained guest file handles per provider. Clones
/// share this quota; closing a handle releases capacity but never recycles its
/// guest-visible number. Root descriptors and transient path-walk descriptors
/// are not part of this limit, so this is not a process-wide descriptor bound.
pub const SANDBOXED_HOST_IO_MAX_OPEN_FILES: usize = 1024;

/// Maximum entropy returned by one guest request. This is intentionally much
/// smaller than the generic host-I/O cap: crypto APIs normally request tens of
/// bytes, while an attacker-controlled allocation must remain bounded before a
/// CSPRNGNG call or transcript clone can occur.
pub const SANDBOXED_HOST_IO_MAX_RANDOM_BYTES_PER_REQUEST: u64 = 1024 * 1024;

/// Total entropy budget for one [`SandboxedHostIo`] instance. The product
/// constructs one provider per run; clones share this atomic budget so a guest
/// cannot multiply authority by making the provider cross interpreter lanes.
pub const SANDBOXED_HOST_IO_RANDOM_BUDGET_BYTES: u64 = 8 * 1024 * 1024;

/// Default shared deadline for a network effect's connect/read/write and TLS
/// handshake. Progress never restarts this budget. The synchronous system DNS
/// resolver cannot be interrupted here; any time it spends is charged once it
/// returns. Product policy must provide bounded resolution when it needs a
/// whole-operation deadline including DNS.
pub const SANDBOXED_HOST_IO_NETWORK_TIMEOUT: Duration = Duration::from_secs(10);

#[cfg(unix)]
#[derive(Debug)]
struct MutationTarget {
    parent: OwnedFd,
    name: OsString,
}

/// Upper bound on symlink traversals during a descriptor-relative read
/// resolution, mirroring the kernel's ELOOP limit for path resolution.
#[cfg(unix)]
const READ_SYMLINK_FOLLOW_CAP: usize = 40;

/// Result of a descriptor-relative read-side resolution. Both variants carry
/// the canonical guest-visible components so `realpath` can render a virtual
/// path without ever consulting the host pathname again.
#[cfg(unix)]
#[derive(Debug)]
enum ReadTarget {
    /// The walk ended holding a directory open (the sandbox root itself, or a
    /// symlink chain ending in `.`/`..`).
    Directory {
        fd: OwnedFd,
        guest_components: Vec<OsString>,
    },
    /// The walk ended at a named final entry inside a held parent directory.
    /// `guest_components` includes `name` as its last element.
    Entry {
        parent: OwnedFd,
        name: OsString,
        guest_components: Vec<OsString>,
    },
}

/// Mutable state of an in-progress descriptor-relative read walk. `dirs`
/// always retains the duplicated sandbox root at index 0; `names` holds the
/// guest-visible component for each directory above the root.
#[cfg(unix)]
struct ReadWalk {
    work: std::collections::VecDeque<OsString>,
    dirs: Vec<OwnedFd>,
    names: Vec<OsString>,
    followed_links: usize,
}

#[cfg(all(test, unix))]
#[derive(Debug)]
struct ResolutionRaceHook {
    trigger_on_resolution: usize,
    resolutions: std::sync::atomic::AtomicUsize,
    resolved: std::sync::Barrier,
    resume: std::sync::Barrier,
}

#[cfg(all(test, unix))]
impl ResolutionRaceHook {
    fn new(trigger_on_resolution: usize) -> std::sync::Arc<Self> {
        assert!(trigger_on_resolution > 0);
        std::sync::Arc::new(Self {
            trigger_on_resolution,
            resolutions: std::sync::atomic::AtomicUsize::new(0),
            resolved: std::sync::Barrier::new(2),
            resume: std::sync::Barrier::new(2),
        })
    }

    fn after_resolution(&self) {
        let resolution = self
            .resolutions
            .fetch_add(1, std::sync::atomic::Ordering::SeqCst)
            + 1;
        if resolution == self.trigger_on_resolution {
            self.resolved.wait();
            self.resume.wait();
        }
    }

    fn wait_until_resolved(&self) {
        self.resolved.wait();
    }

    fn resume(&self) {
        self.resume.wait();
    }
}

/// One open numeric file descriptor in the sandbox fd table (bd-zco6t):
/// the substrate for Node's `fs.openSync`/`writeSync`/`readSync`/`fsyncSync`/
/// `closeSync` lifecycle. The held `File` was opened through the same
/// descriptor-relative containment walk as every other sandboxed operation,
/// so a root rename or path swap after open cannot re-target it.
#[derive(Debug)]
struct SandboxFdEntry {
    file: std::fs::File,
    readable: bool,
    writable: bool,
    /// Guest-visible path, for stable error text only.
    guest_path: String,
}

/// Shared numeric-fd table. Node hands out small integers starting above the
/// stdio triple; the table is monotonic (closed fds are never reissued within
/// a provider lifetime) so a stale guest fd can never alias a newer file.
#[derive(Debug)]
struct SandboxFdTable {
    next_fd: u64,
    max_open_files: usize,
    entries: std::collections::BTreeMap<u64, SandboxFdEntry>,
}

impl SandboxFdTable {
    fn new(max_open_files: usize) -> Self {
        Self {
            // 0/1/2 are the conventional stdio descriptors Node never hands
            // out from fs.openSync.
            next_fd: 3,
            max_open_files,
            entries: std::collections::BTreeMap::new(),
        }
    }
}

/// A real, sandboxed [`HostIoProvider`] that performs genuine filesystem reads
/// and writes confined to a single canonicalized root directory.
///
/// Unlike [`DenyAllHostIo`], this provider *executes* the requested effect: the
/// bytes returned by an `FsRead` are real file contents and an `FsWrite` really
/// hits the disk. It is the engine-side "effect producer" for the proof-carrying
/// host-effect pipeline (bd-f5b04.2.6) — installing it via
/// [`crate::host_io::HostIoProvider`] on the engine's full-caps handler is what
/// makes `dispatches_real_hostcalls()` report `true`. Every operation is:
///
/// * **Capability-checked** — the request's [`HostIoRequest::required_capability`]
///   must be present in `granted`, else [`HostIoError::CapabilityMissing`]
///   (fail-closed; no I/O is attempted).
/// * **Path-confined** — guest paths are interpreted relative to `root`, with a
///   leading slash denoting the guest's virtual root rather than the host root.
///   Empty paths, NUL bytes, backslashes, host prefixes, and traversal (`..`) are
///   rejected lexically. Mutations are rooted at a held directory descriptor
///   and use descriptor-relative, no-follow operations, so a concurrent
///   pathname or symlink swap cannot redirect them outside the sandbox.
///   Read-only operations separately canonicalize and re-check paths.
/// * **Bounded** — reads and writes above `max_bytes` fail closed, defending
///   against parser-bomb / OOM inputs (including a file that grows between
///   `stat` and `read`).
///
/// Network effects (`NetworkSend` / `NetworkRecv`) are also **performed for
/// real** here: a `NetworkSend` opens a TCP connection to the endpoint and
/// writes the payload; a `NetworkRecv` connects and reads a bounded response.
/// Each is capability-checked, byte-bounded against `max_bytes`, and time-bounded
/// by [`SANDBOXED_HOST_IO_NETWORK_TIMEOUT`] so a slow/unreachable peer fails
/// closed instead of hanging.
///
/// SECURITY INVARIANT — the provider is the network *mechanism*, not the network
/// *policy*. It deliberately performs **no** SSRF / egress-allowlist / DNS-rebind
/// check: endpoint authorization is the product layer's responsibility
/// (`franken_node` `security::ssrf_policy` / `network_guard`) and MUST gate the
/// endpoint *before* a `NetworkSend` / `NetworkRecv` request is ever issued to
/// this provider. Duplicating a weaker check here would invite drift; the engine
/// trusts that a request which reaches it has already been authorized. Guest JS
/// does reach this mechanism: `http.get` / `fetch` lower to the engine's
/// `net:request` hostcall and `ClientRequest.end()` issues the same
/// `NetworkRequest`, so an embedder that installs this provider without a
/// destination-policy gate in front of it (franken_node installs
/// `SsrfGatedHostIo`) grants unrestricted egress to any extension holding the
/// network capability (ADR-0015, bd-9vouw.14).
#[derive(Debug, Clone)]
pub struct SandboxedHostIo {
    root: PathBuf,
    /// Stable authority for every filesystem mutation. Holding this descriptor
    /// makes later root-path renames irrelevant to confinement.
    #[cfg(unix)]
    root_fd: std::sync::Arc<OwnedFd>,
    max_bytes: u64,
    network_timeout: Duration,
    /// Network-only containment authority, shared by every provider clone.
    network_revocation: NetworkRevocation,
    random_bytes_remaining: std::sync::Arc<std::sync::atomic::AtomicU64>,
    /// Trust anchors for `use_tls` round trips: the compiled-in webpki (Mozilla)
    /// roots by default, plus any operator-supplied extras added via
    /// [`Self::with_extra_tls_roots_pem`] (private CAs, test anchors). Shared via
    /// `Arc` so cloning the provider does not copy the root set.
    tls_roots: std::sync::Arc<rustls::RootCertStore>,
    #[cfg(all(test, unix))]
    mutation_race_hook: Option<std::sync::Arc<ResolutionRaceHook>>,
    #[cfg(all(test, unix))]
    read_race_hook: Option<std::sync::Arc<ResolutionRaceHook>>,
    /// Numeric fd lifecycle table (bd-zco6t). `Arc`-shared so provider clones
    /// see one table, `Mutex`-guarded because the provider is `Sync`.
    fd_table: std::sync::Arc<std::sync::Mutex<SandboxFdTable>>,
}

impl SandboxedHostIo {
    /// Create a provider rooted at `root` (created if absent, then canonicalized
    /// so later symlink-escape checks compare against the real path), using the
    /// default [`SANDBOXED_HOST_IO_MAX_BYTES`] per-operation cap.
    ///
    /// # Errors
    /// Returns the underlying [`std::io::Error`] if the root cannot be created or
    /// canonicalized.
    pub fn with_root(root: impl Into<PathBuf>) -> std::io::Result<Self> {
        Self::with_root_and_limit(root, SANDBOXED_HOST_IO_MAX_BYTES)
    }

    /// Create a provider with an explicit per-operation byte cap.
    ///
    /// # Errors
    /// Returns the underlying [`std::io::Error`] if the root cannot be created or
    /// canonicalized.
    pub fn with_root_and_limit(root: impl Into<PathBuf>, max_bytes: u64) -> std::io::Result<Self> {
        Self::with_root_and_limits(root, max_bytes, SANDBOXED_HOST_IO_MAX_OPEN_FILES)
    }

    /// Create a provider with explicit per-operation bytes and retained guest
    /// file-handle limits. All clones share the same handle table and quota.
    /// Zero handles is valid: it denies numeric-fd opens without disabling
    /// one-shot reads or writes. The quota is checked before an open can create
    /// or truncate a file; failed opens do not consume quota or handle numbers.
    ///
    /// # Errors
    /// Returns the underlying I/O error if the sandbox root cannot be prepared.
    pub fn with_root_and_limits(
        root: impl Into<PathBuf>,
        max_bytes: u64,
        max_open_files: usize,
    ) -> std::io::Result<Self> {
        let root = root.into();
        std::fs::create_dir_all(&root)?;
        // Canonicalize once so symlink-escape checks compare real paths.
        let root = root.canonicalize()?;
        #[cfg(unix)]
        let root_fd = rustix::fs::open(
            &root,
            rustix::fs::OFlags::RDONLY
                | rustix::fs::OFlags::DIRECTORY
                | rustix::fs::OFlags::NOFOLLOW
                | rustix::fs::OFlags::CLOEXEC,
            rustix::fs::Mode::empty(),
        )
        .map_err(std::io::Error::from)?;
        // bd-3894s slice (5): TLS round trips verify the peer against the
        // compiled-in webpki (Mozilla) roots by default; operators extend the
        // set via `with_extra_tls_roots_pem` (private CAs, test anchors).
        let mut tls_roots = rustls::RootCertStore::empty();
        tls_roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
        Ok(Self {
            root,
            #[cfg(unix)]
            root_fd: std::sync::Arc::new(root_fd),
            max_bytes,
            network_timeout: SANDBOXED_HOST_IO_NETWORK_TIMEOUT,
            network_revocation: NetworkRevocation::default(),
            random_bytes_remaining: std::sync::Arc::new(std::sync::atomic::AtomicU64::new(
                SANDBOXED_HOST_IO_RANDOM_BUDGET_BYTES,
            )),
            tls_roots: std::sync::Arc::new(tls_roots),
            #[cfg(all(test, unix))]
            mutation_race_hook: None,
            #[cfg(all(test, unix))]
            read_race_hook: None,
            fd_table: std::sync::Arc::new(std::sync::Mutex::new(SandboxFdTable::new(
                max_open_files,
            ))),
        })
    }

    #[cfg(all(test, unix))]
    fn with_mutation_race_hook(mut self, hook: std::sync::Arc<ResolutionRaceHook>) -> Self {
        self.mutation_race_hook = Some(hook);
        self
    }

    #[cfg(all(test, unix))]
    fn with_read_race_hook(mut self, hook: std::sync::Arc<ResolutionRaceHook>) -> Self {
        self.read_race_hook = Some(hook);
        self
    }

    /// Set the shared timeout for each network effect, including DNS waiting,
    /// connection attempts, TLS handshake, request writes and response reads. A byte arriving before
    /// a socket timeout does not grant the peer a fresh timeout interval.
    ///
    /// An OS lookup may continue after the caller times out, but at most eight
    /// lookups are in flight across all provider instances. A stuck lookup keeps
    /// its slot; overload fails without spawning more workers. Numeric endpoints
    /// bypass DNS. Address failover happens only before sending any request and
    /// shares this deadline; TLS/HTTP failures never trigger another connection.
    /// Endpoint authorization (including every resolved destination and DNS
    /// rebinding defense) remains the product layer's responsibility.
    ///
    /// # Errors
    /// Zero or an unrepresentable deadline is rejected as `InvalidInput`.
    pub fn with_network_timeout(mut self, timeout: Duration) -> std::io::Result<Self> {
        NetworkDeadline::new(timeout)?;
        self.network_timeout = timeout;
        Ok(self)
    }

    /// Append PEM-encoded certificates to the TLS trust anchors used for
    /// `use_tls` round trips (in addition to the default webpki roots). This is
    /// the seam for operator-configured private CAs and for mock-free tests
    /// that stand up a local TLS listener with a self-signed anchor.
    ///
    /// Fail-closed: an unparseable PEM or a bundle containing no valid
    /// certificate is an error — it never silently degrades to "webpki roots
    /// only" (an operator who configured a private CA must not discover at
    /// request time that it was dropped).
    ///
    /// # Errors
    /// Returns `InvalidData` if the PEM cannot be parsed, a certificate is
    /// rejected by the verifier, or no certificate was added.
    pub fn with_extra_tls_roots_pem(mut self, pem: &[u8]) -> std::io::Result<Self> {
        use rustls_pki_types::CertificateDer;
        use rustls_pki_types::pem::PemObject;
        let mut roots = rustls::RootCertStore::clone(&self.tls_roots);
        let mut added = 0usize;
        for cert in CertificateDer::pem_slice_iter(pem) {
            let cert = cert.map_err(|err| {
                std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    format!("invalid PEM certificate in extra TLS roots: {err:?}"),
                )
            })?;
            roots.add(cert).map_err(|err| {
                std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    format!("rejected extra TLS root certificate: {err}"),
                )
            })?;
            added += 1;
        }
        if added == 0 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "extra TLS roots PEM contained no certificates",
            ));
        }
        self.tls_roots = std::sync::Arc::new(roots);
        Ok(self)
    }

    /// The canonical sandbox root all effects are confined to.
    #[must_use]
    pub fn root(&self) -> &Path {
        &self.root
    }

    /// Lexically resolve a guest-supplied path to an absolute path under `root`.
    /// A leading slash denotes the guest's virtual root; it never selects the
    /// host filesystem root. Does not touch the filesystem; callers additionally
    /// re-check the canonicalized real path to defeat symlink escapes.
    fn confine(&self, raw: &str) -> Result<PathBuf, HostIoError> {
        if raw.is_empty() {
            return Err(HostIoError::SandboxViolation {
                detail: "empty path".to_string(),
            });
        }
        if raw.contains('\0') {
            return Err(HostIoError::SandboxViolation {
                detail: "path contains a NUL byte".to_string(),
            });
        }
        if raw.contains('\\') {
            return Err(HostIoError::SandboxViolation {
                detail: "path contains a backslash".to_string(),
            });
        }
        let mut relative = PathBuf::new();
        for component in Path::new(raw).components() {
            match component {
                Component::Normal(part) => relative.push(part),
                Component::CurDir | Component::RootDir => {}
                Component::ParentDir => {
                    return Err(HostIoError::SandboxViolation {
                        detail: format!("path traversal ('..') is not permitted: {raw}"),
                    });
                }
                Component::Prefix(_) => {
                    return Err(HostIoError::SandboxViolation {
                        detail: format!("host path prefixes are not permitted: {raw}"),
                    });
                }
            }
        }
        let joined = self.root.join(relative);
        // Lexical defense in depth (the component scan already rejects `..`).
        if !joined.starts_with(&self.root) {
            return Err(HostIoError::SandboxViolation {
                detail: format!("resolved path escapes the sandbox root: {raw}"),
            });
        }
        Ok(joined)
    }

    /// Render resolved guest-visible components as an exact virtual absolute
    /// path. The physical root is never exposed, and an unrepresentable
    /// component fails explicitly rather than being replaced with U+FFFD.
    #[cfg(unix)]
    fn render_guest_path(components: &[OsString]) -> Result<String, HostIoError> {
        let mut rendered = String::from("/");
        for component in components {
            let part = component.to_str().ok_or_else(|| HostIoError::Fs {
                code: "EINVAL".to_string(),
                detail: "realpath result contains a non-UTF-8 path component".to_string(),
            })?;
            if part.contains('\\') {
                return Err(HostIoError::Fs {
                    code: "EINVAL".to_string(),
                    detail: "realpath result contains a path component that cannot be represented in the guest path grammar".to_string(),
                });
            }
            if rendered.len() > 1 {
                rendered.push('/');
            }
            rendered.push_str(part);
        }
        Ok(rendered)
    }

    fn fs_error(action: &str, raw: &str, err: std::io::Error) -> HostIoError {
        let code = match err.kind() {
            std::io::ErrorKind::NotFound => "ENOENT",
            std::io::ErrorKind::AlreadyExists => "EEXIST",
            std::io::ErrorKind::NotADirectory => "ENOTDIR",
            std::io::ErrorKind::IsADirectory => "EISDIR",
            std::io::ErrorKind::DirectoryNotEmpty => "ENOTEMPTY",
            std::io::ErrorKind::PermissionDenied => "EACCES",
            std::io::ErrorKind::InvalidInput | std::io::ErrorKind::InvalidData => "EINVAL",
            _ => "EIO",
        };
        HostIoError::Fs {
            code: code.to_string(),
            detail: format!("{action} {raw}: {err}"),
        }
    }

    #[cfg(not(unix))]
    fn fs_not_implemented(action: &str) -> HostIoError {
        HostIoError::NotImplemented {
            what: format!(
                "descriptor-relative filesystem {action} is unavailable on this platform"
            ),
        }
    }

    #[cfg(unix)]
    fn rustix_fs_error(action: &str, raw: &str, err: rustix::io::Errno) -> HostIoError {
        if err == rustix::io::Errno::LOOP {
            HostIoError::SandboxViolation {
                detail: format!("refusing to mutate through a symlink: {raw}"),
            }
        } else {
            Self::fs_error(action, raw, std::io::Error::from(err))
        }
    }

    /// Resolve a guest path for a read-class operation entirely relative to
    /// the held sandbox root descriptor. Every intermediate component is
    /// opened with `NOFOLLOW` against the preceding descriptor; symlinks are
    /// followed only by explicitly reading their target and re-walking it from
    /// the held descriptors, rejecting any hop that would leave the root. No
    /// absolute host pathname survives this function, so a concurrent rename
    /// or symlink swap cannot redirect the post-resolution operation outside
    /// the sandbox.
    ///
    /// `follow_final=false` stops at the final component without following it
    /// so `lstat`/`readlink` can inspect a symlink itself.
    #[cfg(unix)]
    fn read_target(&self, raw: &str, follow_final: bool) -> Result<ReadTarget, HostIoError> {
        self.confine(raw)?;
        let work: std::collections::VecDeque<OsString> = Path::new(raw)
            .components()
            .filter_map(|component| match component {
                Component::Normal(part) => Some(part.to_owned()),
                _ => None,
            })
            .collect();
        let root = rustix::io::dup(self.root_fd.as_ref())
            .map_err(|err| Self::rustix_fs_error("duplicate sandbox root for", raw, err))?;
        let mut walk = ReadWalk {
            work,
            dirs: vec![root],
            names: Vec::new(),
            followed_links: 0,
        };
        let directory_flags = rustix::fs::OFlags::RDONLY
            | rustix::fs::OFlags::DIRECTORY
            | rustix::fs::OFlags::NOFOLLOW
            | rustix::fs::OFlags::CLOEXEC;

        while let Some(part) = walk.work.pop_front() {
            if part == OsStr::new(".") {
                continue;
            }
            if part == OsStr::new("..") {
                if walk.names.pop().is_none() {
                    return Err(HostIoError::SandboxViolation {
                        detail: format!("symlinked path escapes the sandbox root: {raw}"),
                    });
                }
                walk.dirs.pop();
                continue;
            }
            let parent = walk
                .dirs
                .last()
                .expect("read walk retains the sandbox root");
            if walk.work.is_empty() {
                if follow_final {
                    let stat =
                        rustix::fs::statat(parent, &part, rustix::fs::AtFlags::SYMLINK_NOFOLLOW)
                            .map_err(|err| Self::rustix_fs_error("resolve", raw, err))?;
                    if rustix::fs::FileType::from_raw_mode(stat.st_mode).is_symlink() {
                        let target = Self::read_symlink_component(parent, &part, raw)?;
                        self.queue_symlink_target(&mut walk, &target, raw)?;
                        continue;
                    }
                }
                let parent = walk.dirs.pop().expect("read walk retains the sandbox root");
                walk.names.push(part.clone());
                #[cfg(test)]
                if let Some(hook) = &self.read_race_hook {
                    hook.after_resolution();
                }
                return Ok(ReadTarget::Entry {
                    parent,
                    name: part,
                    guest_components: walk.names,
                });
            }
            match rustix::fs::openat(parent, &part, directory_flags, rustix::fs::Mode::empty()) {
                Ok(opened) => {
                    walk.dirs.push(opened);
                    walk.names.push(part);
                }
                Err(err)
                    if matches!(err, rustix::io::Errno::NOTDIR | rustix::io::Errno::LOOP)
                        && rustix::fs::statat(
                            parent,
                            &part,
                            rustix::fs::AtFlags::SYMLINK_NOFOLLOW,
                        )
                        .is_ok_and(|stat| {
                            rustix::fs::FileType::from_raw_mode(stat.st_mode).is_symlink()
                        }) =>
                {
                    let target = Self::read_symlink_component(parent, &part, raw)?;
                    self.queue_symlink_target(&mut walk, &target, raw)?;
                }
                Err(err) => {
                    return Err(Self::rustix_fs_error("resolve parent for", raw, err));
                }
            }
        }

        // Every component was consumed while holding a directory open: the
        // sandbox root itself, or a symlink chain ending in `.`/`..`.
        let fd = walk.dirs.pop().expect("read walk retains the sandbox root");
        #[cfg(test)]
        if let Some(hook) = &self.read_race_hook {
            hook.after_resolution();
        }
        Ok(ReadTarget::Directory {
            fd,
            guest_components: walk.names,
        })
    }

    /// Read the stored target of an in-sandbox symlink component relative to
    /// its held parent descriptor.
    #[cfg(unix)]
    fn read_symlink_component(
        parent: &OwnedFd,
        name: &OsStr,
        raw: &str,
    ) -> Result<PathBuf, HostIoError> {
        use std::os::unix::ffi::OsStrExt;
        let target = rustix::fs::readlinkat(parent, name, Vec::new())
            .map_err(|err| Self::rustix_fs_error("readlink", raw, err))?;
        Ok(PathBuf::from(OsStr::from_bytes(target.as_bytes())))
    }

    /// Queue a symlink target for continued resolution. Relative targets keep
    /// walking from the current held directory; absolute targets are honored
    /// only when they lexically re-enter the sandbox root (they restart from
    /// the held root descriptor) and are rejected otherwise. Depth is bounded
    /// so link cycles fail closed with `ELOOP`.
    #[cfg(unix)]
    fn queue_symlink_target(
        &self,
        walk: &mut ReadWalk,
        target: &Path,
        raw: &str,
    ) -> Result<(), HostIoError> {
        walk.followed_links += 1;
        if walk.followed_links > READ_SYMLINK_FOLLOW_CAP {
            return Err(HostIoError::Fs {
                code: "ELOOP".to_string(),
                detail: format!("too many levels of symbolic links: {raw}"),
            });
        }
        let relative: PathBuf = if target.has_root() {
            match target.strip_prefix(&self.root) {
                Ok(rest) => {
                    let root = rustix::io::dup(self.root_fd.as_ref()).map_err(|err| {
                        Self::rustix_fs_error("duplicate sandbox root for", raw, err)
                    })?;
                    walk.dirs.clear();
                    walk.dirs.push(root);
                    walk.names.clear();
                    rest.to_path_buf()
                }
                Err(_) => {
                    return Err(HostIoError::SandboxViolation {
                        detail: format!("symlinked path escapes the sandbox root: {raw}"),
                    });
                }
            }
        } else {
            target.to_path_buf()
        };
        let mut queued: Vec<OsString> = Vec::new();
        for component in relative.components() {
            match component {
                Component::Normal(part) => queued.push(part.to_owned()),
                Component::CurDir => {}
                Component::ParentDir => queued.push(OsString::from("..")),
                Component::RootDir | Component::Prefix(_) => {
                    return Err(HostIoError::SandboxViolation {
                        detail: format!("symlinked path escapes the sandbox root: {raw}"),
                    });
                }
            }
        }
        for component in queued.into_iter().rev() {
            walk.work.push_front(component);
        }
        Ok(())
    }

    /// Map a post-resolution reopen failure. `ELOOP` (and `ENOTDIR` when the
    /// entry is now a symlink) means the final entry was swapped for a symlink
    /// after resolution; refuse to follow it.
    #[cfg(unix)]
    fn read_reopen_error(
        parent: &OwnedFd,
        name: &OsStr,
        action: &str,
        raw: &str,
        err: rustix::io::Errno,
    ) -> HostIoError {
        if err == rustix::io::Errno::LOOP
            || (err == rustix::io::Errno::NOTDIR
                && rustix::fs::statat(parent, name, rustix::fs::AtFlags::SYMLINK_NOFOLLOW)
                    .is_ok_and(|stat| {
                        rustix::fs::FileType::from_raw_mode(stat.st_mode).is_symlink()
                    }))
        {
            HostIoError::SandboxViolation {
                detail: format!("refusing to follow a symlink introduced after resolution: {raw}"),
            }
        } else {
            Self::fs_error(action, raw, std::io::Error::from(err))
        }
    }

    /// Build the transported metadata shape directly from a descriptor-relative
    /// `stat` result.
    #[cfg(unix)]
    fn stat_metadata_result(stat: &rustix::fs::Stat) -> FsMetadata {
        let file_type = rustix::fs::FileType::from_raw_mode(stat.st_mode);
        let total_millis =
            i128::from(stat.st_mtime) * 1000 + i128::from(stat.st_mtime_nsec) / 1_000_000;
        let modified_millis = i64::try_from(total_millis).unwrap_or(if total_millis > 0 {
            i64::MAX
        } else {
            i64::MIN
        });
        FsMetadata {
            size: u64::try_from(stat.st_size).unwrap_or(0),
            // `st_mode` is u16 on Apple platforms and u32 elsewhere.
            #[allow(clippy::useless_conversion)]
            mode: u32::from(stat.st_mode),
            modified_millis,
            is_file: file_type.is_file(),
            is_directory: file_type.is_dir(),
            is_symbolic_link: file_type.is_symlink(),
        }
    }

    /// Resolve a mutation target to a stable parent-directory capability and a
    /// single final name. Every intermediate component is opened relative to
    /// the preceding descriptor with `NOFOLLOW`; no absolute pathname survives
    /// this function. A rename or symlink swap after resolution therefore
    /// cannot redirect the caller to a different directory.
    #[cfg(unix)]
    fn mutation_target(
        &self,
        raw: &str,
        create_parents: bool,
    ) -> Result<MutationTarget, HostIoError> {
        self.confine(raw)?;
        let normal: Vec<&OsStr> = Path::new(raw)
            .components()
            .filter_map(|component| match component {
                Component::Normal(part) => Some(part),
                _ => None,
            })
            .collect();
        let Some((file_name, parents)) = normal.split_last() else {
            return Err(HostIoError::SandboxViolation {
                detail: format!("path resolves to no file name: {raw}"),
            });
        };
        let mut current = rustix::io::dup(self.root_fd.as_ref())
            .map_err(|err| Self::rustix_fs_error("duplicate sandbox root for", raw, err))?;
        let directory_flags = rustix::fs::OFlags::RDONLY
            | rustix::fs::OFlags::DIRECTORY
            | rustix::fs::OFlags::NOFOLLOW
            | rustix::fs::OFlags::CLOEXEC;
        for part in parents {
            let opened = match rustix::fs::openat(
                &current,
                *part,
                directory_flags,
                rustix::fs::Mode::empty(),
            ) {
                Ok(opened) => opened,
                Err(err) if create_parents && err == rustix::io::Errno::NOENT => {
                    match rustix::fs::mkdirat(
                        &current,
                        *part,
                        rustix::fs::Mode::from_raw_mode(0o777),
                    ) {
                        Ok(()) => {}
                        // Another actor may have created the component. The
                        // no-follow open below is the authoritative check.
                        Err(err) if err == rustix::io::Errno::EXIST => {}
                        Err(err) => {
                            return Err(Self::rustix_fs_error("create parent for", raw, err));
                        }
                    }
                    rustix::fs::openat(&current, *part, directory_flags, rustix::fs::Mode::empty())
                        .map_err(|err| Self::mutation_component_error(&current, part, raw, err))?
                }
                Err(err) => {
                    return Err(Self::mutation_component_error(&current, part, raw, err));
                }
            };
            current = opened;
        }

        #[cfg(test)]
        if let Some(hook) = &self.mutation_race_hook {
            hook.after_resolution();
        }

        Ok(MutationTarget {
            parent: current,
            name: (*file_name).to_owned(),
        })
    }

    #[cfg(unix)]
    fn mutation_component_error(
        parent: &OwnedFd,
        component: &OsStr,
        raw: &str,
        err: rustix::io::Errno,
    ) -> HostIoError {
        if matches!(err, rustix::io::Errno::NOTDIR | rustix::io::Errno::LOOP)
            && rustix::fs::statat(parent, component, rustix::fs::AtFlags::SYMLINK_NOFOLLOW)
                .is_ok_and(|stat| rustix::fs::FileType::from_raw_mode(stat.st_mode).is_symlink())
        {
            HostIoError::SandboxViolation {
                detail: format!("refusing to traverse a symlinked directory: {raw}"),
            }
        } else {
            Self::rustix_fs_error("resolve parent for", raw, err)
        }
    }

    #[cfg(unix)]
    fn open_mutation_file(
        target: &MutationTarget,
        flags: rustix::fs::OFlags,
        raw: &str,
        action: &str,
    ) -> Result<std::fs::File, HostIoError> {
        let descriptor = rustix::fs::openat(
            &target.parent,
            &target.name,
            flags | rustix::fs::OFlags::NOFOLLOW | rustix::fs::OFlags::CLOEXEC,
            rustix::fs::Mode::from_raw_mode(0o666),
        )
        .map_err(|err| Self::rustix_fs_error(action, raw, err))?;
        Ok(std::fs::File::from(descriptor))
    }

    #[cfg(unix)]
    fn mkdir_target(
        target: &MutationTarget,
        raw: &str,
        recursive: bool,
    ) -> Result<(), HostIoError> {
        match rustix::fs::mkdirat(
            &target.parent,
            &target.name,
            rustix::fs::Mode::from_raw_mode(0o777),
        ) {
            Ok(()) => Ok(()),
            Err(err) if recursive && err == rustix::io::Errno::EXIST => rustix::fs::openat(
                &target.parent,
                &target.name,
                rustix::fs::OFlags::RDONLY
                    | rustix::fs::OFlags::DIRECTORY
                    | rustix::fs::OFlags::NOFOLLOW
                    | rustix::fs::OFlags::CLOEXEC,
                rustix::fs::Mode::empty(),
            )
            .map(|_| ())
            .map_err(|err| Self::rustix_fs_error("mkdir", raw, err)),
            Err(err) => Err(Self::rustix_fs_error("mkdir", raw, err)),
        }
    }

    #[cfg(unix)]
    fn remove_directory_contents(directory: &OwnedFd, raw: &str) -> Result<(), HostIoError> {
        let mut entries = rustix::fs::Dir::read_from(directory)
            .map_err(|err| Self::rustix_fs_error("open directory for remove", raw, err))?;
        while let Some(entry) = entries.read() {
            let entry = entry
                .map_err(|err| Self::rustix_fs_error("read directory for remove", raw, err))?;
            let name = entry.file_name();
            if matches!(name.to_bytes(), b"." | b"..") {
                continue;
            }
            let stat = rustix::fs::statat(directory, name, rustix::fs::AtFlags::SYMLINK_NOFOLLOW)
                .map_err(|err| {
                Self::rustix_fs_error("stat before recursive remove", raw, err)
            })?;
            if rustix::fs::FileType::from_raw_mode(stat.st_mode).is_dir() {
                let child = rustix::fs::openat(
                    directory,
                    name,
                    rustix::fs::OFlags::RDONLY
                        | rustix::fs::OFlags::DIRECTORY
                        | rustix::fs::OFlags::NOFOLLOW
                        | rustix::fs::OFlags::CLOEXEC,
                    rustix::fs::Mode::empty(),
                )
                .map_err(|err| Self::rustix_fs_error("open directory for remove", raw, err))?;
                Self::remove_directory_contents(&child, raw)?;
                rustix::fs::unlinkat(directory, name, rustix::fs::AtFlags::REMOVEDIR)
                    .map_err(|err| Self::rustix_fs_error("remove directory", raw, err))?;
            } else {
                rustix::fs::unlinkat(directory, name, rustix::fs::AtFlags::empty())
                    .map_err(|err| Self::rustix_fs_error("remove file", raw, err))?;
            }
        }
        Ok(())
    }

    #[cfg(unix)]
    fn remove_target(
        target: &MutationTarget,
        raw: &str,
        recursive: bool,
        force: bool,
    ) -> Result<(), HostIoError> {
        let stat = match rustix::fs::statat(
            &target.parent,
            &target.name,
            rustix::fs::AtFlags::SYMLINK_NOFOLLOW,
        ) {
            Ok(stat) => stat,
            Err(err) if force && err == rustix::io::Errno::NOENT => return Ok(()),
            Err(err) => return Err(Self::rustix_fs_error("stat before remove", raw, err)),
        };
        let outcome = if rustix::fs::FileType::from_raw_mode(stat.st_mode).is_dir() {
            if recursive {
                let directory = rustix::fs::openat(
                    &target.parent,
                    &target.name,
                    rustix::fs::OFlags::RDONLY
                        | rustix::fs::OFlags::DIRECTORY
                        | rustix::fs::OFlags::NOFOLLOW
                        | rustix::fs::OFlags::CLOEXEC,
                    rustix::fs::Mode::empty(),
                )
                .map_err(|err| Self::rustix_fs_error("open directory for remove", raw, err))?;
                Self::remove_directory_contents(&directory, raw)?;
            }
            rustix::fs::unlinkat(&target.parent, &target.name, rustix::fs::AtFlags::REMOVEDIR)
        } else {
            rustix::fs::unlinkat(&target.parent, &target.name, rustix::fs::AtFlags::empty())
        };
        match outcome {
            Ok(()) => Ok(()),
            Err(err) if force && err == rustix::io::Errno::NOENT => Ok(()),
            Err(err) => Err(Self::rustix_fs_error("remove", raw, err)),
        }
    }

    fn fs_read(&self, raw: &str) -> HostIoOutcome {
        #[cfg(not(unix))]
        {
            let _ = raw;
            Err(Self::fs_not_implemented("read"))
        }
        #[cfg(unix)]
        {
            let ReadTarget::Entry { parent, name, .. } = self.read_target(raw, true)? else {
                return Err(HostIoError::Fs {
                    code: "EISDIR".to_string(),
                    detail: format!("not a regular file: {raw}"),
                });
            };
            // NONBLOCK so an entry swapped for a FIFO after resolution errors
            // on the type check below instead of blocking the host.
            let descriptor = rustix::fs::openat(
                &parent,
                &name,
                rustix::fs::OFlags::RDONLY
                    | rustix::fs::OFlags::NOFOLLOW
                    | rustix::fs::OFlags::NONBLOCK
                    | rustix::fs::OFlags::CLOEXEC,
                rustix::fs::Mode::empty(),
            )
            .map_err(|err| Self::read_reopen_error(&parent, &name, "open", raw, err))?;
            let file = std::fs::File::from(descriptor);
            let metadata = file
                .metadata()
                .map_err(|err| Self::fs_error("stat", raw, err))?;
            if !metadata.is_file() {
                return Err(HostIoError::Fs {
                    code: "EISDIR".to_string(),
                    detail: format!("not a regular file: {raw}"),
                });
            }
            if metadata.len() > self.max_bytes {
                return Err(HostIoError::Io {
                    detail: format!(
                        "file {raw} is {} bytes, exceeds the {}-byte read cap",
                        metadata.len(),
                        self.max_bytes
                    ),
                });
            }
            // Bounded read: cap+1 so a file that grew between stat and read
            // still fails closed rather than being silently truncated.
            let mut bytes = Vec::new();
            file.take(self.max_bytes.saturating_add(1))
                .read_to_end(&mut bytes)
                .map_err(|err| Self::fs_error("read", raw, err))?;
            if u64::try_from(bytes.len()).unwrap_or(u64::MAX) > self.max_bytes {
                return Err(HostIoError::Io {
                    detail: format!("file {raw} exceeds the {}-byte read cap", self.max_bytes),
                });
            }
            Ok(HostIoResponse::FsRead { bytes })
        }
    }

    fn fs_write(&self, raw: &str, data: &[u8]) -> HostIoOutcome {
        if u64::try_from(data.len()).unwrap_or(u64::MAX) > self.max_bytes {
            return Err(HostIoError::Io {
                detail: format!(
                    "write of {} bytes to {raw} exceeds the {}-byte cap",
                    data.len(),
                    self.max_bytes
                ),
            });
        }
        #[cfg(not(unix))]
        {
            let _ = (raw, data);
            Err(Self::fs_not_implemented("write"))
        }
        #[cfg(unix)]
        {
            let target = self.mutation_target(raw, false)?;
            let mut file = Self::open_mutation_file(
                &target,
                rustix::fs::OFlags::WRONLY | rustix::fs::OFlags::CREATE | rustix::fs::OFlags::TRUNC,
                raw,
                "open for write",
            )?;
            file.write_all(data)
                .map_err(|err| Self::fs_error("write", raw, err))?;
            Ok(HostIoResponse::FsWrite {
                bytes_written: u64::try_from(data.len()).unwrap_or(u64::MAX),
            })
        }
    }

    /// Look up an open fd entry, mapping an unknown or already-closed fd to
    /// Node's `EBADF` (bd-zco6t).
    fn with_fd_entry<T>(
        &self,
        fd: u64,
        action: impl FnOnce(&mut SandboxFdEntry) -> Result<T, HostIoError>,
    ) -> Result<T, HostIoError> {
        let mut table = self.fd_table.lock().map_err(|_| HostIoError::Io {
            detail: "sandbox fd table lock poisoned".to_string(),
        })?;
        let Some(entry) = table.entries.get_mut(&fd) else {
            return Err(HostIoError::Fs {
                code: "EBADF".to_string(),
                detail: format!("bad file descriptor: {fd}"),
            });
        };
        action(entry)
    }

    /// Node `fs.openSync(path, flags)` substrate (bd-zco6t): resolve `raw`
    /// through the same descriptor-relative containment walk as every other
    /// sandboxed operation, open it under the requested Node flag string, and
    /// hand back a monotonic numeric fd. Supported flags: `r`, `r+`, `w`,
    /// `w+`, `a`, `a+`. Unknown flags fail with `ERR_INVALID_ARG_VALUE`
    /// before any filesystem effect. Retained-handle capacity and sequence
    /// exhaustion return `EMFILE` before opening, creating or truncating. The
    /// table lock keeps admission atomic across clones. Nonblocking opens
    /// ensure a FIFO cannot wait for a peer before the regular-file check.
    ///
    /// # Errors
    /// `EMFILE`, invalid flags and containment failures surface as [`HostIoError`].
    pub fn open_fd(&self, raw: &str, flags: &str) -> Result<u64, HostIoError> {
        #[cfg(not(unix))]
        {
            let _ = (raw, flags);
            Err(Self::fs_not_implemented("open"))
        }
        #[cfg(unix)]
        {
            let (readable, writable, base_flags) = match flags {
                "r" => (true, false, rustix::fs::OFlags::RDONLY),
                "r+" => (true, true, rustix::fs::OFlags::RDWR),
                "w" => (
                    false,
                    true,
                    rustix::fs::OFlags::WRONLY
                        | rustix::fs::OFlags::CREATE
                        | rustix::fs::OFlags::TRUNC,
                ),
                "w+" => (
                    true,
                    true,
                    rustix::fs::OFlags::RDWR
                        | rustix::fs::OFlags::CREATE
                        | rustix::fs::OFlags::TRUNC,
                ),
                "a" => (
                    false,
                    true,
                    rustix::fs::OFlags::WRONLY
                        | rustix::fs::OFlags::CREATE
                        | rustix::fs::OFlags::APPEND,
                ),
                "a+" => (
                    true,
                    true,
                    rustix::fs::OFlags::RDWR
                        | rustix::fs::OFlags::CREATE
                        | rustix::fs::OFlags::APPEND,
                ),
                other => {
                    return Err(HostIoError::Fs {
                        code: "ERR_INVALID_ARG_VALUE".to_string(),
                        detail: format!("unsupported fs open flags: {other}"),
                    });
                }
            };
            // Admission must precede even O_TRUNC/O_CREAT. Holding the table
            // through insertion prevents concurrent clones from spending the
            // final slot twice. Ordinary regular-file I/O ignores NONBLOCK;
            // a FIFO must not block here before metadata can reject it.
            let mut table = self.fd_table.lock().map_err(|_| HostIoError::Io {
                detail: "sandbox fd table lock poisoned".to_string(),
            })?;
            if table.entries.len() >= table.max_open_files {
                return Err(HostIoError::Fs {
                    code: "EMFILE".to_string(),
                    detail: "sandbox guest file-handle limit reached".to_string(),
                });
            }
            let fd = table.next_fd;
            let next_fd = fd.checked_add(1).ok_or_else(|| HostIoError::Fs {
                code: "EMFILE".to_string(),
                detail: "sandbox guest file-handle sequence exhausted".to_string(),
            })?;
            let base_flags = base_flags | rustix::fs::OFlags::NONBLOCK | rustix::fs::OFlags::NOCTTY;
            let file = if writable {
                let target = self.mutation_target(raw, false)?;
                Self::open_mutation_file(&target, base_flags, raw, "open")?
            } else {
                let ReadTarget::Entry { parent, name, .. } = self.read_target(raw, true)? else {
                    return Err(HostIoError::Fs {
                        code: "EISDIR".to_string(),
                        detail: format!("not a regular file: {raw}"),
                    });
                };
                let descriptor = rustix::fs::openat(
                    &parent,
                    &name,
                    base_flags | rustix::fs::OFlags::NOFOLLOW | rustix::fs::OFlags::CLOEXEC,
                    rustix::fs::Mode::empty(),
                )
                .map_err(|err| Self::rustix_fs_error("open", raw, err))?;
                std::fs::File::from(descriptor)
            };
            let metadata = file
                .metadata()
                .map_err(|err| Self::fs_error("stat", raw, err))?;
            if !metadata.is_file() {
                return Err(HostIoError::Fs {
                    code: "EISDIR".to_string(),
                    detail: format!("not a regular file: {raw}"),
                });
            }
            table.next_fd = next_fd;
            table.entries.insert(
                fd,
                SandboxFdEntry {
                    file,
                    readable,
                    writable,
                    guest_path: raw.to_string(),
                },
            );
            Ok(fd)
        }
    }

    /// Write at an open descriptor's cursor, retaining the existing API.
    /// Positioned callers use [`Self::write_fd_at`] instead; no seek-based
    /// emulation may alter the cursor shared by provider clones.
    pub fn write_fd(&self, fd: u64, data: &[u8]) -> Result<u64, HostIoError> {
        self.write_fd_at(fd, data, None)
    }

    /// Node `fs.readSync(fd, buffer, offset, length, position)` substrate
    /// (bd-zco6t): read up to `length` bytes. With `position: Some(_)` the
    /// read is positional (`pread`) and — matching Node — does NOT move the
    /// fd's cursor; with `None` it reads at the cursor and advances it.
    /// Returns the bytes actually read (shorter at end-of-file).
    ///
    /// # Errors
    /// `EBADF` for unknown/write-only fds; the per-operation byte cap applies.
    pub fn read_fd(
        &self,
        fd: u64,
        length: u64,
        position: Option<u64>,
    ) -> Result<Vec<u8>, HostIoError> {
        if length > self.max_bytes {
            return Err(HostIoError::Io {
                detail: format!(
                    "read of {length} bytes from fd {fd} exceeds the {}-byte cap",
                    self.max_bytes
                ),
            });
        }
        self.with_fd_entry(fd, |entry| {
            if !entry.readable {
                return Err(HostIoError::Fs {
                    code: "EBADF".to_string(),
                    detail: format!("fd {fd} ({}) is not open for reading", entry.guest_path),
                });
            }
            let capacity = usize::try_from(length).unwrap_or(usize::MAX);
            let mut buffer = vec![0u8; capacity];
            let mut filled = 0usize;
            while filled < buffer.len() {
                let read = if let Some(base) = position {
                    // Positional reads are pread-shaped: the fd cursor stays
                    // where sequential reads left it, matching Node.
                    #[cfg(unix)]
                    {
                        let offset = base.saturating_add(filled as u64);
                        std::os::unix::fs::FileExt::read_at(
                            &entry.file,
                            &mut buffer[filled..],
                            offset,
                        )
                    }
                    #[cfg(not(unix))]
                    {
                        let _ = base;
                        return Err(Self::fs_not_implemented("pread"));
                    }
                } else {
                    std::io::Read::read(&mut entry.file, &mut buffer[filled..])
                }
                .map_err(|err| Self::fs_error("read", &entry.guest_path.clone(), err))?;
                if read == 0 {
                    break;
                }
                filled += read;
            }
            buffer.truncate(filled);
            Ok(buffer)
        })
    }

    /// Node `fs.fsyncSync(fd)` substrate (bd-zco6t): flush the file and its
    /// metadata to stable storage.
    ///
    /// # Errors
    /// `EBADF` for an unknown fd; I/O failures surface as filesystem errors.
    pub fn fsync_fd(&self, fd: u64) -> Result<(), HostIoError> {
        self.with_fd_entry(fd, |entry| {
            entry
                .file
                .sync_all()
                .map_err(|err| Self::fs_error("fsync", &entry.guest_path.clone(), err))
        })
    }

    /// Node `fs.closeSync(fd)` substrate (bd-zco6t): drop the entry (closing
    /// the descriptor). The numeric fd is never reissued by this provider, so
    /// a stale guest fd stays `EBADF` forever instead of aliasing a newer
    /// file.
    ///
    /// # Errors
    /// `EBADF` for an unknown or already-closed fd.
    pub fn close_fd(&self, fd: u64) -> Result<(), HostIoError> {
        let mut table = self.fd_table.lock().map_err(|_| HostIoError::Io {
            detail: "sandbox fd table lock poisoned".to_string(),
        })?;
        if table.entries.remove(&fd).is_none() {
            return Err(HostIoError::Fs {
                code: "EBADF".to_string(),
                detail: format!("bad file descriptor: {fd}"),
            });
        }
        Ok(())
    }

    /// Parse the `fd=` argument of an fd-shaped operation. A missing or
    /// non-numeric fd is `EBADF` — the same guest-visible failure an unknown
    /// descriptor produces (bd-zco6t).
    fn fs_fd_argument(arguments: &[String]) -> Result<u64, HostIoError> {
        Self::fs_argument(arguments, "fd")
            .and_then(|value| value.parse::<u64>().ok())
            .ok_or_else(|| HostIoError::Fs {
                code: "EBADF".to_string(),
                detail: "bad file descriptor argument".to_string(),
            })
    }

    fn fs_argument<'a>(arguments: &'a [String], name: &str) -> Option<&'a str> {
        arguments.iter().find_map(|argument| {
            argument
                .strip_prefix(name)
                .and_then(|value| value.strip_prefix('='))
        })
    }

    fn fs_flag(arguments: &[String], name: &str) -> bool {
        Self::fs_argument(arguments, name) == Some("true")
    }

    fn fs_meta(
        &self,
        operation: FsOperation,
        raw: &str,
        arguments: &[String],
        data: &[u8],
    ) -> HostIoOutcome {
        let result = match operation {
            FsOperation::Read | FsOperation::Write => {
                return Err(HostIoError::NotImplemented {
                    what: format!("fs_meta cannot route the {} keystone", operation.as_str()),
                });
            }
            // Numeric fd lifecycle (bd-zco6t): delegate to the sandbox fd
            // table. `raw` is meaningful only for Open (the path being
            // opened); fd-shaped operations identify their target through the
            // `fd=` argument and ignore the path field.
            FsOperation::Open => {
                let flags = Self::fs_argument(arguments, "flags").unwrap_or("r");
                FsMetaResult::Unsigned(self.open_fd(raw, flags)?)
            }
            FsOperation::WriteFd => {
                let fd = Self::fs_fd_argument(arguments)?;
                let position = fd_write::position_argument(arguments)?;
                FsMetaResult::Unsigned(self.write_fd_at(fd, data, position)?)
            }
            FsOperation::ReadFd => {
                let fd = Self::fs_fd_argument(arguments)?;
                let length = Self::fs_argument(arguments, "length")
                    .and_then(|value| value.parse::<u64>().ok())
                    .unwrap_or(0);
                let position = Self::fs_argument(arguments, "position")
                    .and_then(|value| value.parse::<u64>().ok());
                FsMetaResult::Bytes(self.read_fd(fd, length, position)?)
            }
            FsOperation::Fsync => {
                self.fsync_fd(Self::fs_fd_argument(arguments)?)?;
                FsMetaResult::Unit
            }
            FsOperation::CloseFd => {
                self.close_fd(Self::fs_fd_argument(arguments)?)?;
                FsMetaResult::Unit
            }
            FsOperation::Append => {
                if u64::try_from(data.len()).unwrap_or(u64::MAX) > self.max_bytes {
                    return Err(HostIoError::Io {
                        detail: format!(
                            "append of {} bytes to {raw} exceeds the {}-byte cap",
                            data.len(),
                            self.max_bytes
                        ),
                    });
                }
                #[cfg(not(unix))]
                {
                    return Err(Self::fs_not_implemented("append"));
                }
                #[cfg(unix)]
                {
                    let target = self.mutation_target(raw, false)?;
                    let mut file = Self::open_mutation_file(
                        &target,
                        rustix::fs::OFlags::WRONLY
                            | rustix::fs::OFlags::CREATE
                            | rustix::fs::OFlags::APPEND,
                        raw,
                        "open for append",
                    )?;
                    file.write_all(data)
                        .map_err(|err| Self::fs_error("append", raw, err))?;
                    FsMetaResult::Unsigned(u64::try_from(data.len()).unwrap_or(u64::MAX))
                }
            }
            FsOperation::Exists => {
                #[cfg(not(unix))]
                {
                    return Err(Self::fs_not_implemented("exists"));
                }
                #[cfg(unix)]
                {
                    match self.read_target(raw, true) {
                        Ok(_) => FsMetaResult::Bool(true),
                        Err(HostIoError::Fs { code, .. })
                            if code == "ENOENT" || code == "ENOTDIR" =>
                        {
                            FsMetaResult::Bool(false)
                        }
                        Err(err) => return Err(err),
                    }
                }
            }
            FsOperation::Mkdir => {
                let recursive = Self::fs_flag(arguments, "recursive");
                #[cfg(not(unix))]
                {
                    let _ = recursive;
                    return Err(Self::fs_not_implemented("mkdir"));
                }
                #[cfg(unix)]
                {
                    let target = self.mutation_target(raw, recursive)?;
                    Self::mkdir_target(&target, raw, recursive)?;
                    FsMetaResult::Unit
                }
            }
            FsOperation::ReadDir => {
                #[cfg(not(unix))]
                {
                    return Err(Self::fs_not_implemented("readdir"));
                }
                #[cfg(unix)]
                {
                    let with_file_types = Self::fs_flag(arguments, "with_file_types");
                    let directory = match self.read_target(raw, true)? {
                        ReadTarget::Directory { fd, .. } => fd,
                        ReadTarget::Entry { parent, name, .. } => rustix::fs::openat(
                            &parent,
                            &name,
                            rustix::fs::OFlags::RDONLY
                                | rustix::fs::OFlags::DIRECTORY
                                | rustix::fs::OFlags::NOFOLLOW
                                | rustix::fs::OFlags::CLOEXEC,
                            rustix::fs::Mode::empty(),
                        )
                        .map_err(|err| {
                            Self::read_reopen_error(&parent, &name, "readdir", raw, err)
                        })?,
                    };
                    let mut names = Vec::new();
                    let mut entries = Vec::new();
                    let mut directory_entries = rustix::fs::Dir::read_from(&directory)
                        .map_err(|err| Self::fs_error("readdir", raw, std::io::Error::from(err)))?;
                    while let Some(entry) = directory_entries.read() {
                        let entry = entry.map_err(|err| {
                            Self::fs_error("readdir entry", raw, std::io::Error::from(err))
                        })?;
                        let file_name = entry.file_name();
                        if matches!(file_name.to_bytes(), b"." | b"..") {
                            continue;
                        }
                        let name = String::from_utf8_lossy(file_name.to_bytes()).into_owned();
                        if with_file_types {
                            let stat = rustix::fs::statat(
                                &directory,
                                file_name,
                                rustix::fs::AtFlags::SYMLINK_NOFOLLOW,
                            )
                            .map_err(|err| {
                                Self::fs_error("stat readdir entry", raw, std::io::Error::from(err))
                            })?;
                            let file_type = rustix::fs::FileType::from_raw_mode(stat.st_mode);
                            entries.push(FsDirEntry {
                                name,
                                is_file: file_type.is_file(),
                                is_directory: file_type.is_dir(),
                                is_symbolic_link: file_type.is_symlink(),
                            });
                        } else {
                            names.push(name);
                        }
                    }
                    if with_file_types {
                        FsMetaResult::DirEntries(entries)
                    } else {
                        FsMetaResult::Strings(names)
                    }
                }
            }
            FsOperation::Stat | FsOperation::Lstat => {
                #[cfg(not(unix))]
                {
                    return Err(Self::fs_not_implemented(operation.as_str()));
                }
                #[cfg(unix)]
                {
                    let follow_final = operation == FsOperation::Stat;
                    let stat = match self.read_target(raw, follow_final)? {
                        ReadTarget::Directory { fd, .. } => {
                            rustix::fs::fstat(&fd).map_err(|err| {
                                Self::fs_error(operation.as_str(), raw, std::io::Error::from(err))
                            })?
                        }
                        ReadTarget::Entry { parent, name, .. } => rustix::fs::statat(
                            &parent,
                            &name,
                            rustix::fs::AtFlags::SYMLINK_NOFOLLOW,
                        )
                        .map_err(|err| {
                            Self::fs_error(operation.as_str(), raw, std::io::Error::from(err))
                        })?,
                    };
                    FsMetaResult::Metadata(Self::stat_metadata_result(&stat))
                }
            }
            FsOperation::Symlink => {
                let link_raw = arguments.first().ok_or_else(|| HostIoError::Fs {
                    code: "EINVAL".to_string(),
                    detail: "symlink requires a destination path".to_string(),
                })?;
                if Path::new(raw).has_root() {
                    // The kernel interprets a stored absolute symlink target in
                    // the host namespace. Until guest-absolute targets have a
                    // dedicated encoding, preserve the previous fail-closed
                    // behavior rather than writing a host-rooted link.
                    return Err(HostIoError::SandboxViolation {
                        detail: format!(
                            "virtual-absolute symlink targets are not supported: {raw}"
                        ),
                    });
                }
                self.confine(raw)?;
                #[cfg(unix)]
                {
                    let link = self.mutation_target(link_raw, false)?;
                    rustix::fs::symlinkat(raw, &link.parent, &link.name)
                        .map_err(|err| Self::rustix_fs_error("symlink", link_raw, err))?;
                }
                #[cfg(not(unix))]
                {
                    return Err(Self::fs_not_implemented("symlink"));
                }
                FsMetaResult::Unit
            }
            FsOperation::ReadLink => {
                #[cfg(not(unix))]
                {
                    return Err(Self::fs_not_implemented("readlink"));
                }
                #[cfg(unix)]
                {
                    let ReadTarget::Entry { parent, name, .. } = self.read_target(raw, false)?
                    else {
                        return Err(HostIoError::SandboxViolation {
                            detail: format!("path resolves to no final component: {raw}"),
                        });
                    };
                    let link =
                        rustix::fs::readlinkat(&parent, &name, Vec::new()).map_err(|err| {
                            Self::fs_error("readlink", raw, std::io::Error::from(err))
                        })?;
                    FsMetaResult::String(String::from_utf8_lossy(link.as_bytes()).into_owned())
                }
            }
            FsOperation::Rename | FsOperation::CopyFile => {
                let destination_raw = arguments.first().ok_or_else(|| HostIoError::Fs {
                    code: "EINVAL".to_string(),
                    detail: format!("{} requires a destination path", operation.as_str()),
                })?;
                #[cfg(not(unix))]
                {
                    let _ = destination_raw;
                    return Err(Self::fs_not_implemented(operation.as_str()));
                }
                #[cfg(unix)]
                {
                    let source = self.mutation_target(raw, false)?;
                    let destination = self.mutation_target(destination_raw, false)?;
                    if operation == FsOperation::Rename {
                        rustix::fs::renameat(
                            &source.parent,
                            &source.name,
                            &destination.parent,
                            &destination.name,
                        )
                        .map_err(|err| Self::rustix_fs_error("rename", raw, err))?;
                    } else {
                        let mut source_file = Self::open_mutation_file(
                            &source,
                            rustix::fs::OFlags::RDONLY,
                            raw,
                            "open copy source",
                        )?;
                        let source_metadata = source_file
                            .metadata()
                            .map_err(|err| Self::fs_error("stat copy source", raw, err))?;
                        if !source_metadata.is_file() {
                            return Err(HostIoError::Fs {
                                code: "EISDIR".to_string(),
                                detail: format!("copy source is not a regular file: {raw}"),
                            });
                        }
                        let mut destination_file = Self::open_mutation_file(
                            &destination,
                            rustix::fs::OFlags::WRONLY
                                | rustix::fs::OFlags::CREATE
                                | rustix::fs::OFlags::TRUNC,
                            destination_raw,
                            "open copy destination",
                        )?;
                        std::io::copy(&mut source_file, &mut destination_file)
                            .map_err(|err| Self::fs_error("copy", raw, err))?;
                        destination_file
                            .set_permissions(source_metadata.permissions())
                            .map_err(|err| Self::fs_error("copy permissions", raw, err))?;
                    }
                    FsMetaResult::Unit
                }
            }
            FsOperation::Unlink => {
                #[cfg(not(unix))]
                {
                    return Err(Self::fs_not_implemented("unlink"));
                }
                #[cfg(unix)]
                {
                    let target = self.mutation_target(raw, false)?;
                    rustix::fs::unlinkat(
                        &target.parent,
                        &target.name,
                        rustix::fs::AtFlags::empty(),
                    )
                    .map_err(|err| Self::rustix_fs_error("unlink", raw, err))?;
                    FsMetaResult::Unit
                }
            }
            FsOperation::Remove => {
                let recursive = Self::fs_flag(arguments, "recursive");
                let force = Self::fs_flag(arguments, "force");
                #[cfg(not(unix))]
                {
                    let _ = (recursive, force);
                    return Err(Self::fs_not_implemented("remove"));
                }
                #[cfg(unix)]
                {
                    let target = match self.mutation_target(raw, false) {
                        Ok(target) => target,
                        Err(HostIoError::Fs { code, .. }) if force && code == "ENOENT" => {
                            return Ok(HostIoResponse::FsMeta {
                                result: FsMetaResult::Unit,
                            });
                        }
                        Err(err) => return Err(err),
                    };
                    Self::remove_target(&target, raw, recursive, force)?;
                    FsMetaResult::Unit
                }
            }
            FsOperation::RemoveDir => {
                #[cfg(not(unix))]
                {
                    return Err(Self::fs_not_implemented("rmdir"));
                }
                #[cfg(unix)]
                {
                    let target = self.mutation_target(raw, false)?;
                    rustix::fs::unlinkat(
                        &target.parent,
                        &target.name,
                        rustix::fs::AtFlags::REMOVEDIR,
                    )
                    .map_err(|err| Self::rustix_fs_error("rmdir", raw, err))?;
                    FsMetaResult::Unit
                }
            }
            FsOperation::Truncate => {
                let length = arguments
                    .first()
                    .and_then(|value| value.parse::<u64>().ok())
                    .unwrap_or(0);
                #[cfg(not(unix))]
                {
                    let _ = length;
                    return Err(Self::fs_not_implemented("truncate"));
                }
                #[cfg(unix)]
                {
                    let target = self.mutation_target(raw, false)?;
                    let file = Self::open_mutation_file(
                        &target,
                        rustix::fs::OFlags::WRONLY,
                        raw,
                        "open for truncate",
                    )?;
                    file.set_len(length)
                        .map_err(|err| Self::fs_error("truncate", raw, err))?;
                    FsMetaResult::Unit
                }
            }
            FsOperation::Access => {
                #[cfg(not(unix))]
                {
                    return Err(Self::fs_not_implemented("access"));
                }
                #[cfg(unix)]
                {
                    self.read_target(raw, true)?;
                    FsMetaResult::Unit
                }
            }
            FsOperation::Chmod => {
                let mode = arguments
                    .first()
                    .and_then(|value| value.parse::<u32>().ok())
                    .ok_or_else(|| HostIoError::Fs {
                        code: "EINVAL".to_string(),
                        detail: format!("chmod requires a numeric mode: {raw}"),
                    })?;
                #[cfg(unix)]
                {
                    let target = self.mutation_target(raw, false)?;
                    let file = Self::open_mutation_file(
                        &target,
                        rustix::fs::OFlags::RDONLY | rustix::fs::OFlags::NONBLOCK,
                        raw,
                        "open for chmod",
                    )?;
                    // `RawMode` is u16 on Apple platforms and u32 elsewhere.
                    #[allow(clippy::useless_conversion, clippy::unnecessary_fallible_conversions)]
                    let raw_mode =
                        rustix::fs::RawMode::try_from(mode).map_err(|_| HostIoError::Fs {
                            code: "EINVAL".to_string(),
                            detail: format!("chmod mode out of range: {raw}"),
                        })?;
                    rustix::fs::fchmod(&file, rustix::fs::Mode::from_raw_mode(raw_mode))
                        .map_err(|err| Self::rustix_fs_error("chmod", raw, err))?;
                }
                #[cfg(not(unix))]
                {
                    let _ = mode;
                    return Err(Self::fs_not_implemented("chmod"));
                }
                FsMetaResult::Unit
            }
            FsOperation::Utimes => {
                let modified_millis = arguments
                    .get(1)
                    .or_else(|| arguments.first())
                    .and_then(|value| value.parse::<u64>().ok())
                    .ok_or_else(|| HostIoError::Fs {
                        code: "EINVAL".to_string(),
                        detail: format!("utimes requires numeric millisecond timestamps: {raw}"),
                    })?;
                let modified = std::time::UNIX_EPOCH
                    .checked_add(std::time::Duration::from_millis(modified_millis))
                    .ok_or_else(|| HostIoError::Fs {
                        code: "EINVAL".to_string(),
                        detail: format!("utimes timestamp is out of range: {modified_millis}"),
                    })?;
                #[cfg(not(unix))]
                {
                    let _ = modified;
                    return Err(Self::fs_not_implemented("utimes"));
                }
                #[cfg(unix)]
                {
                    let target = self.mutation_target(raw, false)?;
                    let file = Self::open_mutation_file(
                        &target,
                        rustix::fs::OFlags::WRONLY,
                        raw,
                        "open for utimes",
                    )?;
                    file.set_times(std::fs::FileTimes::new().set_modified(modified))
                        .map_err(|err| Self::fs_error("utimes", raw, err))?;
                    FsMetaResult::Unit
                }
            }
            FsOperation::Realpath => {
                #[cfg(not(unix))]
                {
                    return Err(Self::fs_not_implemented("realpath"));
                }
                #[cfg(unix)]
                {
                    let guest_components = match self.read_target(raw, true)? {
                        ReadTarget::Directory {
                            guest_components, ..
                        }
                        | ReadTarget::Entry {
                            guest_components, ..
                        } => guest_components,
                    };
                    FsMetaResult::String(Self::render_guest_path(&guest_components)?)
                }
            }
            FsOperation::Mkdtemp => {
                self.confine(raw)?;
                #[cfg(not(unix))]
                {
                    return Err(Self::fs_not_implemented("mkdtemp"));
                }
                #[cfg(unix)]
                {
                    let mut created = None;
                    for suffix in 0_u32..1_000_000 {
                        let candidate_raw = format!("{raw}{suffix:06}");
                        let candidate = self.mutation_target(&candidate_raw, false)?;
                        match rustix::fs::mkdirat(
                            &candidate.parent,
                            &candidate.name,
                            rustix::fs::Mode::from_raw_mode(0o777),
                        ) {
                            Ok(()) => {
                                created = Some(candidate_raw);
                                break;
                            }
                            Err(err) if err == rustix::io::Errno::EXIST => {}
                            Err(err) => return Err(Self::rustix_fs_error("mkdtemp", raw, err)),
                        }
                    }
                    FsMetaResult::String(created.ok_or_else(|| HostIoError::Fs {
                        code: "EEXIST".to_string(),
                        detail: format!(
                            "unable to allocate a unique temporary directory for {raw}"
                        ),
                    })?)
                }
            }
        };
        Ok(HostIoResponse::FsMeta { result })
    }

    /// Connect without renewing the operation's budget on individual I/O calls.
    /// DNS admission and caller waiting are bounded by the same deadline.
    /// Endpoint authorization remains the product's policy; this mechanism
    /// does not broaden authority or retry a partially sent request.
    fn connect(
        &self,
        endpoint: &str,
        deadline: NetworkDeadline,
    ) -> Result<DeadlineTcpStream, HostIoError> {
        if endpoint.is_empty() {
            return Err(HostIoError::SandboxViolation {
                detail: "empty network endpoint".to_string(),
            });
        }
        if endpoint.contains('\0') {
            return Err(HostIoError::SandboxViolation {
                detail: "network endpoint contains a NUL byte".to_string(),
            });
        }
        DeadlineTcpStream::connect_endpoint(endpoint, deadline).map_err(|err| HostIoError::Io {
            detail: format!("resolve/connect {endpoint}: {err}"),
        })
    }

    fn network_send(
        &self,
        endpoint: &str,
        payload: &[u8],
        deadline: NetworkDeadline,
    ) -> HostIoOutcome {
        if u64::try_from(payload.len()).unwrap_or(u64::MAX) > self.max_bytes {
            return Err(HostIoError::Io {
                detail: format!(
                    "network send of {} bytes to {endpoint} exceeds the {}-byte cap",
                    payload.len(),
                    self.max_bytes
                ),
            });
        }
        let mut stream = self.connect(endpoint, deadline)?;
        stream.write_all(payload).map_err(|err| HostIoError::Io {
            detail: format!("send to {endpoint}: {err}"),
        })?;
        stream.flush().map_err(|err| HostIoError::Io {
            detail: format!("flush to {endpoint}: {err}"),
        })?;
        Ok(HostIoResponse::NetworkSend {
            bytes_sent: u64::try_from(payload.len()).unwrap_or(u64::MAX),
        })
    }

    fn random_read(&self, byte_len: u64) -> HostIoOutcome {
        use rand::RngCore;
        use std::sync::atomic::Ordering;

        let per_request_cap = self
            .max_bytes
            .min(SANDBOXED_HOST_IO_MAX_RANDOM_BYTES_PER_REQUEST);
        if byte_len > per_request_cap {
            return Err(HostIoError::Io {
                detail: format!(
                    "random read of {byte_len} bytes exceeds the {per_request_cap}-byte per-request cap"
                ),
            });
        }
        let byte_len_usize = usize::try_from(byte_len).map_err(|_| HostIoError::Io {
            detail: format!("random read of {byte_len} bytes exceeds host addressable memory"),
        })?;
        if self
            .random_bytes_remaining
            .try_update(Ordering::AcqRel, Ordering::Acquire, |remaining| {
                remaining.checked_sub(byte_len)
            })
            .is_err()
        {
            return Err(HostIoError::Io {
                detail: format!(
                    "random read of {byte_len} bytes exceeds the remaining per-run entropy budget"
                ),
            });
        }

        let mut bytes = vec![0u8; byte_len_usize];
        if let Err(error) = rand::rngs::OsRng.try_fill_bytes(&mut bytes) {
            self.random_bytes_remaining
                .fetch_add(byte_len, Ordering::AcqRel);
            return Err(HostIoError::Io {
                detail: format!("operating-system CSPRNG unavailable: {error}"),
            });
        }
        Ok(HostIoResponse::RandomRead { bytes })
    }

    fn network_recv(
        &self,
        endpoint: &str,
        max_len: u64,
        deadline: NetworkDeadline,
    ) -> HostIoOutcome {
        // Bound the read by the smaller of the caller-requested length and the
        // provider's per-operation cap.
        let cap = max_len.min(self.max_bytes);
        let mut stream = self.connect(endpoint, deadline)?;
        let mut bytes = Vec::new();
        // Bounded read: cap+1 so a peer that streams more than the cap fails
        // closed rather than being silently truncated.
        Read::by_ref(&mut stream)
            .take(cap.saturating_add(1))
            .read_to_end(&mut bytes)
            .map_err(|err| HostIoError::Io {
                detail: format!("recv from {endpoint}: {err}"),
            })?;
        if u64::try_from(bytes.len()).unwrap_or(u64::MAX) > cap {
            return Err(HostIoError::Io {
                detail: format!("network recv from {endpoint} exceeds the {cap}-byte cap"),
            });
        }
        stream.check_active().map_err(|err| HostIoError::Io {
            detail: format!("recv completion from {endpoint}: {err}"),
        })?;
        Ok(HostIoResponse::NetworkRecv { bytes })
    }

    /// A single-socket request/response round trip: connect once, write the
    /// framed `payload`, flush, then read the reply back on the *same* socket
    /// (bounded by `min(max_len, max_bytes)`). This is the mechanism behind a
    /// guest `http.get`/`fetch`: the response bytes returned here are the real
    /// status line + headers + body the peer sent, which the engine parses into a
    /// JS response object. Self-delimited replies finish at their HTTP message
    /// boundary, even on a persistent connection. Truncated framed replies are
    /// errors, not partial successful responses.
    fn network_request(
        &self,
        endpoint: &str,
        payload: &[u8],
        max_len: u64,
        use_tls: bool,
        deadline: NetworkDeadline,
    ) -> HostIoOutcome {
        if u64::try_from(payload.len()).unwrap_or(u64::MAX) > self.max_bytes {
            return Err(HostIoError::Io {
                detail: format!(
                    "network request payload of {} bytes to {endpoint} exceeds the {}-byte cap",
                    payload.len(),
                    self.max_bytes
                ),
            });
        }
        // Bound the response read by the smaller of the caller-requested length
        // and the provider's per-operation cap.
        let cap = max_len.min(self.max_bytes);
        if use_tls {
            return self.network_request_tls(endpoint, payload, cap, deadline);
        }
        let mut stream = self.connect(endpoint, deadline)?;
        stream.write_all(payload).map_err(|err| HostIoError::Io {
            detail: format!("send to {endpoint}: {err}"),
        })?;
        stream.flush().map_err(|err| HostIoError::Io {
            detail: format!("flush to {endpoint}: {err}"),
        })?;
        // Half-close the write direction: we send nothing more on this connection,
        // so signal end-of-request to the peer. This lets a peer that reads the
        // request to EOF (rather than parsing its framing) respond and close, and
        // it leaves our read half open to receive the reply. Best-effort: a peer
        // that already closed makes this a no-op.
        let _ = stream.shutdown(Shutdown::Write);
        let response = http_response::read_response(&mut stream, payload, cap).map_err(|err| {
            HostIoError::Io {
                detail: format!("HTTP recv from {endpoint}: {err}"),
            }
        })?;
        stream.check_active().map_err(|err| HostIoError::Io {
            detail: format!("HTTP completion from {endpoint}: {err}"),
        })?;
        Ok(HostIoResponse::NetworkRequest { response })
    }

    /// bd-3894s slice (5): the TLS variant of the single-socket round trip. The
    /// TCP stream (already connect/read/write time-bounded by `connect`) is
    /// wrapped in a real rustls client session before the framed request is
    /// written; the server certificate is verified against `tls_roots` (webpki
    /// defaults plus operator extras) with SNI/verification identity taken from
    /// the endpoint's host part (DNS name or IP address). Handshake, write, and
    /// read failures all fail closed — there is no silent plaintext fallback.
    ///
    /// Unlike the plaintext path, no TCP write-half-close precedes the read: a
    /// TCP FIN inside a TLS session is a truncation signal, not end-of-request.
    /// Request termination is carried by the HTTP framing itself
    /// (`Content-Length` + `Connection: close` synthesized by the engine's wire
    /// builder). A fully received length-delimited or chunked message needs no
    /// TLS close notification; a close-delimited body requires a clean TLS EOF.
    fn network_request_tls(
        &self,
        endpoint: &str,
        payload: &[u8],
        cap: u64,
        deadline: NetworkDeadline,
    ) -> HostIoOutcome {
        // Authenticate the requested DNS name, never whichever IP happened to
        // connect. Numeric IPv4/IPv6 endpoints use the IP subjectAlternativeName
        // without SNI; the brackets and numeric scope are transport syntax only.
        let server_name = match endpoint.parse::<std::net::SocketAddr>() {
            Ok(address) => rustls_pki_types::ServerName::from(address.ip()),
            Err(_) => {
                let host = endpoint.rsplit_once(':').map_or(endpoint, |(host, _)| host);
                rustls_pki_types::ServerName::try_from(host.to_string()).map_err(|err| {
                    HostIoError::Io {
                        detail: format!("invalid TLS server name {host}: {err}"),
                    }
                })?
            }
        };
        let provider = std::sync::Arc::new(rustls::crypto::ring::default_provider());
        let config = rustls::ClientConfig::builder_with_provider(provider)
            .with_safe_default_protocol_versions()
            .map_err(|err| HostIoError::Io {
                detail: format!("TLS protocol setup for {endpoint}: {err}"),
            })?
            .with_root_certificates(rustls::RootCertStore::clone(&self.tls_roots))
            .with_no_client_auth();
        let conn = rustls::ClientConnection::new(std::sync::Arc::new(config), server_name)
            .map_err(|err| HostIoError::Io {
                detail: format!("TLS client setup for {endpoint}: {err}"),
            })?;
        let stream = self.connect(endpoint, deadline)?;
        let mut tls = rustls::StreamOwned::new(conn, stream);
        tls.write_all(payload).map_err(|err| HostIoError::Io {
            detail: format!("TLS send to {endpoint}: {err}"),
        })?;
        tls.flush().map_err(|err| HostIoError::Io {
            detail: format!("TLS flush to {endpoint}: {err}"),
        })?;
        // rustls reports a missing close_notify as UnexpectedEof. Never turn
        // that into success unless framing already completed the message (in
        // which case the reader returns before asking TLS for another byte).
        let response = http_response::read_response(&mut tls, payload, cap).map_err(|err| {
            HostIoError::Io {
                detail: format!("TLS HTTP recv from {endpoint}: {err}"),
            }
        })?;
        tls.sock.check_active().map_err(|err| HostIoError::Io {
            detail: format!("TLS HTTP completion from {endpoint}: {err}"),
        })?;
        Ok(HostIoResponse::NetworkRequest { response })
    }
}

impl HostIoProvider for SandboxedHostIo {
    fn name(&self) -> &str {
        "sandboxed-host-io"
    }

    fn filesystem_exception_provenance(&self) -> HostIoExceptionProvenance {
        HostIoExceptionProvenance::ProviderInternal
    }

    fn perform(&self, request: &HostIoRequest, granted: &[HostIoCapability]) -> HostIoOutcome {
        self.perform_controlled(
            request,
            granted,
            std::sync::Arc::new(UnrestrictedHostIoControl),
        )
    }

    fn perform_controlled(
        &self,
        request: &HostIoRequest,
        granted: &[HostIoCapability],
        control: std::sync::Arc<dyn HostIoControl>,
    ) -> HostIoOutcome {
        let required = request.required_capability();
        if !capability_granted(granted, required) {
            return Err(HostIoError::CapabilityMissing {
                capability: required,
            });
        }
        if request.is_network() {
            return self.run_controlled_network(control, |deadline| match request {
                HostIoRequest::NetworkSend { endpoint, payload } => {
                    self.network_send(endpoint, payload, deadline)
                }
                HostIoRequest::NetworkRecv { endpoint, max_len } => {
                    self.network_recv(endpoint, *max_len, deadline)
                }
                HostIoRequest::NetworkRequest {
                    endpoint,
                    payload,
                    max_len,
                    use_tls,
                } => self.network_request(endpoint, payload, *max_len, *use_tls, deadline),
                _ => unreachable!("network request classified above"),
            });
        }
        control::OperationControl::new(control).check_host()?;
        match request {
            HostIoRequest::FsRead { path } => self.fs_read(path),
            HostIoRequest::FsWrite { path, data } => self.fs_write(path, data),
            HostIoRequest::FsMeta {
                operation,
                path,
                arguments,
                data,
            } => self.fs_meta(*operation, path, arguments, data),
            HostIoRequest::RandomRead { byte_len } => self.random_read(*byte_len),
            HostIoRequest::EnvRead { .. } => Err(HostIoError::Denied {
                reason: "no explicit environment snapshot installed".to_string(),
            }),
            _ => unreachable!("network request handled above"),
        }
    }
}

/// Recorder mode for deterministic host I/O replay.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HostIoReplayMode {
    Record,
    Replay,
}

/// Deterministic-replay recorder for host I/O.
pub trait HostIoRecorder: core::fmt::Debug + Send + Sync {
    /// Declare whether filesystem errors supplied by this recorder are bounded
    /// to typed request plus internal state. The fail-closed default covers
    /// custom replay sources. A transparent recording-only implementation may
    /// return [`HostIoExceptionProvenance::ProviderInternal`].
    fn filesystem_exception_provenance(&self) -> HostIoExceptionProvenance {
        HostIoExceptionProvenance::Unknown
    }

    /// Begin one orchestrated execution before any host effect can run.
    ///
    /// Implementations use this boundary to reject unsupported lifecycle
    /// semantics before a live provider can perform an irreversible effect.
    fn begin_execution(&self) -> Result<(), HostIoError>;

    /// In replay mode, return the recorded outcome for the next matching
    /// request. In record mode, return `None` so the live provider runs.
    fn replay(&self, request: &HostIoRequest) -> Option<HostIoOutcome>;

    /// In record mode, append a completed host I/O request and outcome.
    fn record(&self, request: &HostIoRequest, outcome: &HostIoOutcome);

    /// Finish the current execution and return exactly the transcript belonging
    /// to that execution.
    ///
    /// The execution orchestrator calls this after every interpreter attempt,
    /// before it derives risk, evidence, or receipts. Replay implementations
    /// must reject a prior divergence and every unused suffix. Recording
    /// implementations must return only entries appended since the matching
    /// [`Self::begin_execution`] call.
    ///
    /// Both lifecycle methods are required: a custom recorder cannot opt into
    /// preflight while accidentally inheriting a late, post-effect failure.
    fn finish_execution(&self) -> Result<Vec<(HostIoRequest, HostIoOutcome)>, HostIoError>;

    /// Snapshot the recorded `(request, outcome)` transcript so callers (e.g. the
    /// diagnostics can inspect the recorder's complete lifetime history.
    /// Per-execution attestation must use [`Self::finish_execution`], never this
    /// cumulative snapshot. Recorders that do not retain history return an empty
    /// vec by default.
    fn recorded_entries(&self) -> Vec<(HostIoRequest, HostIoOutcome)> {
        Vec::new()
    }
}

/// In-memory transcript reference implementation.
#[derive(Debug)]
pub struct InMemoryHostIoTranscript {
    mode: HostIoReplayMode,
    entries: std::sync::Mutex<Vec<(HostIoRequest, HostIoOutcome)>>,
    execution_state: std::sync::Mutex<HostIoExecutionState>,
}

#[derive(Debug, Default)]
enum HostIoExecutionState {
    #[default]
    Idle,
    Recording {
        start: usize,
    },
    Replaying {
        cursor: usize,
    },
    Finalized,
    Poisoned(HostIoError),
}

impl InMemoryHostIoTranscript {
    #[must_use]
    pub fn recording() -> Self {
        Self {
            mode: HostIoReplayMode::Record,
            entries: std::sync::Mutex::new(Vec::new()),
            execution_state: std::sync::Mutex::new(HostIoExecutionState::default()),
        }
    }

    /// Construct a single-execution replay transcript.
    ///
    /// Replay state is intentionally not resettable: after exact finalization it
    /// remains exhausted, and after failed finalization it remains poisoned.
    /// Callers that execute again must install a fresh replay transcript.
    #[must_use]
    pub fn replaying(entries: Vec<(HostIoRequest, HostIoOutcome)>) -> Self {
        Self {
            mode: HostIoReplayMode::Replay,
            entries: std::sync::Mutex::new(entries),
            execution_state: std::sync::Mutex::new(HostIoExecutionState::default()),
        }
    }

    #[must_use]
    pub fn mode(&self) -> HostIoReplayMode {
        self.mode
    }

    #[must_use]
    pub fn entries(&self) -> Vec<(HostIoRequest, HostIoOutcome)> {
        self.entries
            .lock()
            .expect("host I/O transcript mutex")
            .clone()
    }

    #[must_use]
    pub fn len(&self) -> usize {
        self.entries
            .lock()
            .expect("host I/O transcript mutex")
            .len()
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.entries
            .lock()
            .expect("host I/O transcript mutex")
            .is_empty()
    }
}

impl HostIoRecorder for InMemoryHostIoTranscript {
    fn filesystem_exception_provenance(&self) -> HostIoExceptionProvenance {
        match self.mode {
            HostIoReplayMode::Record => HostIoExceptionProvenance::ProviderInternal,
            HostIoReplayMode::Replay => HostIoExceptionProvenance::Unknown,
        }
    }

    fn begin_execution(&self) -> Result<(), HostIoError> {
        let mut state = self
            .execution_state
            .lock()
            .expect("host I/O execution state mutex");
        match &*state {
            HostIoExecutionState::Idle => {
                *state = match self.mode {
                    HostIoReplayMode::Record => {
                        let start = self
                            .entries
                            .lock()
                            .expect("host I/O transcript mutex")
                            .len();
                        HostIoExecutionState::Recording { start }
                    }
                    HostIoReplayMode::Replay => HostIoExecutionState::Replaying { cursor: 0 },
                };
                Ok(())
            }
            HostIoExecutionState::Poisoned(error) => Err(error.clone()),
            HostIoExecutionState::Finalized => Err(HostIoError::Denied {
                reason: "host I/O replay transcript already finalized".to_string(),
            }),
            HostIoExecutionState::Recording { .. } | HostIoExecutionState::Replaying { .. } => {
                Err(HostIoError::Denied {
                    reason: "host I/O transcript execution already active".to_string(),
                })
            }
        }
    }

    fn replay(&self, request: &HostIoRequest) -> Option<HostIoOutcome> {
        if self.mode != HostIoReplayMode::Replay {
            return None;
        }

        let mut state = self
            .execution_state
            .lock()
            .expect("host I/O execution state mutex");
        let idx = match &*state {
            HostIoExecutionState::Replaying { cursor } => *cursor,
            HostIoExecutionState::Poisoned(error) => return Some(Err(error.clone())),
            HostIoExecutionState::Finalized => {
                return Some(Err(HostIoError::Denied {
                    reason: "host I/O replay transcript already finalized".to_string(),
                }));
            }
            HostIoExecutionState::Idle => {
                let error = HostIoError::Denied {
                    reason: "host I/O replay attempted before begin_execution".to_string(),
                };
                *state = HostIoExecutionState::Poisoned(error.clone());
                return Some(Err(error));
            }
            HostIoExecutionState::Recording { .. } => {
                let error = HostIoError::Denied {
                    reason: "host I/O replay state is inconsistent with recorder mode".to_string(),
                };
                *state = HostIoExecutionState::Poisoned(error.clone());
                return Some(Err(error));
            }
        };

        let entries = self.entries.lock().expect("host I/O transcript mutex");
        match entries.get(idx) {
            Some((recorded_request, outcome)) if recorded_request == request => {
                *state = HostIoExecutionState::Replaying { cursor: idx + 1 };
                Some(outcome.clone())
            }
            Some((recorded_request, _)) => {
                let error = HostIoError::SandboxViolation {
                    detail: format!(
                        "host I/O replay divergence at index {idx}: live {} != recorded {}",
                        request.kind(),
                        recorded_request.kind()
                    ),
                };
                *state = HostIoExecutionState::Poisoned(error.clone());
                Some(Err(error))
            }
            None => {
                let error = HostIoError::Denied {
                    reason: format!("host I/O replay transcript exhausted at index {idx}"),
                };
                *state = HostIoExecutionState::Poisoned(error.clone());
                Some(Err(error))
            }
        }
    }

    fn record(&self, request: &HostIoRequest, outcome: &HostIoOutcome) {
        if self.mode != HostIoReplayMode::Record {
            return;
        }

        self.entries
            .lock()
            .expect("host I/O transcript mutex")
            .push((request.clone(), outcome.clone()));
    }

    fn finish_execution(&self) -> Result<Vec<(HostIoRequest, HostIoOutcome)>, HostIoError> {
        let mut state = self
            .execution_state
            .lock()
            .expect("host I/O execution state mutex");
        let entries = self.entries.lock().expect("host I/O transcript mutex");
        match &*state {
            HostIoExecutionState::Recording { start } => {
                let current = entries.get(*start..).ok_or_else(|| HostIoError::Denied {
                    reason: "host I/O recording boundary exceeds transcript length".to_string(),
                })?;
                let current = current.to_vec();
                *state = HostIoExecutionState::Idle;
                Ok(current)
            }
            HostIoExecutionState::Replaying { cursor } if *cursor == entries.len() => {
                let current = entries.clone();
                *state = HostIoExecutionState::Finalized;
                Ok(current)
            }
            HostIoExecutionState::Replaying { cursor } => {
                let error = HostIoError::Denied {
                    reason: format!(
                        "host I/O replay finished with {} unused transcript entries starting at index {}",
                        entries.len() - *cursor,
                        cursor
                    ),
                };
                *state = HostIoExecutionState::Poisoned(error.clone());
                Err(error)
            }
            HostIoExecutionState::Poisoned(error) => Err(error.clone()),
            HostIoExecutionState::Finalized => Err(HostIoError::Denied {
                reason: "host I/O replay transcript already finalized".to_string(),
            }),
            HostIoExecutionState::Idle => Err(HostIoError::Denied {
                reason: "host I/O transcript execution was not begun".to_string(),
            }),
        }
    }

    fn recorded_entries(&self) -> Vec<(HostIoRequest, HostIoOutcome)> {
        self.entries()
    }
}

#[cfg(test)]
mod tests;
