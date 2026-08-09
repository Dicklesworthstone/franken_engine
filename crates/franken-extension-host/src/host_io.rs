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
use std::net::{Shutdown, TcpStream, ToSocketAddrs};
#[cfg(unix)]
use std::os::fd::OwnedFd;
use std::path::{Component, Path, PathBuf};
use std::time::Duration;

/// Capability a guest must hold for the host to perform a given I/O request.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum HostIoCapability {
    FsRead,
    FsWrite,
    NetworkSend,
    NetworkRecv,
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
            | Self::Mkdtemp => HostIoCapability::FsWrite,
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
}

impl HostIoCapability {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::FsRead => "fs_read",
            Self::FsWrite => "fs_write",
            Self::NetworkSend => "network_send",
            Self::NetworkRecv => "network_recv",
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
}

impl HostIoRequest {
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

/// A sandboxed host I/O provider.
pub trait HostIoProvider: core::fmt::Debug + Send + Sync {
    fn name(&self) -> &str;

    /// Perform `request` using only the capabilities explicitly granted.
    ///
    /// Implementations must verify [`HostIoRequest::required_capability`] is
    /// present in `granted` before doing I/O and must fail closed otherwise.
    fn perform(&self, request: &HostIoRequest, granted: &[HostIoCapability]) -> HostIoOutcome;
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
}

#[must_use]
pub fn capability_granted(granted: &[HostIoCapability], required: HostIoCapability) -> bool {
    granted.contains(&required)
}

/// Default per-operation byte cap for [`SandboxedHostIo`] (16 MiB). Bounds memory
/// use and provides a parser-bomb / OOM defense; mirrors the franken_node CAS
/// per-blob cap.
pub const SANDBOXED_HOST_IO_MAX_BYTES: u64 = 16 * 1024 * 1024;

/// Per-operation network timeout for [`SandboxedHostIo`] connect/read/write.
/// Bounds how long a single guest network effect may block so a slow or
/// unreachable endpoint fails closed deterministically instead of hanging the
/// runtime (a hung effect would also stall replay/transcript determinism).
pub const SANDBOXED_HOST_IO_NETWORK_TIMEOUT: Duration = Duration::from_secs(10);

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
/// trusts that a request which reaches it has already been authorized. (Today no
/// guest JS path lowers to a network hostcall — `create_effect_from_hostcall_tag`
/// has no network arm — so this mechanism stays dormant until that lowering and
/// the product-layer SSRF gate land together.)
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

#[derive(Debug, Clone)]
pub struct SandboxedHostIo {
    root: PathBuf,
    /// Stable authority for every filesystem mutation. Holding this descriptor
    /// makes later root-path renames irrelevant to confinement.
    #[cfg(unix)]
    root_fd: std::sync::Arc<OwnedFd>,
    max_bytes: u64,
    /// Trust anchors for `use_tls` round trips: the compiled-in webpki (Mozilla)
    /// roots by default, plus any operator-supplied extras added via
    /// [`Self::with_extra_tls_roots_pem`] (private CAs, test anchors). Shared via
    /// `Arc` so cloning the provider does not copy the root set.
    tls_roots: std::sync::Arc<rustls::RootCertStore>,
    #[cfg(all(test, unix))]
    mutation_race_hook: Option<std::sync::Arc<ResolutionRaceHook>>,
    #[cfg(all(test, unix))]
    read_race_hook: Option<std::sync::Arc<ResolutionRaceHook>>,
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
            tls_roots: std::sync::Arc::new(tls_roots),
            #[cfg(all(test, unix))]
            mutation_race_hook: None,
            #[cfg(all(test, unix))]
            read_race_hook: None,
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
            mode: stat.st_mode,
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
                    rustix::fs::fchmod(&file, rustix::fs::Mode::from_raw_mode(mode))
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

    /// Open a time-bounded TCP connection to `endpoint`.
    ///
    /// This performs **no** SSRF / egress-policy check — endpoint authorization
    /// is the product layer's responsibility and must happen before the request
    /// reaches this provider (see the type-level SECURITY INVARIANT). The
    /// connection carries a bounded connect/read/write timeout so a slow or
    /// unreachable peer fails closed instead of hanging.
    fn connect(&self, endpoint: &str) -> Result<TcpStream, HostIoError> {
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
        // Resolve to a concrete socket address so a bounded connect timeout can
        // be applied (`TcpStream::connect` itself takes no timeout).
        let addr = endpoint
            .to_socket_addrs()
            .map_err(|err| HostIoError::Io {
                detail: format!("resolve {endpoint}: {err}"),
            })?
            .next()
            .ok_or_else(|| HostIoError::Io {
                detail: format!("resolve {endpoint}: no addresses"),
            })?;
        let stream = TcpStream::connect_timeout(&addr, SANDBOXED_HOST_IO_NETWORK_TIMEOUT).map_err(
            |err| HostIoError::Io {
                detail: format!("connect {endpoint}: {err}"),
            },
        )?;
        stream
            .set_read_timeout(Some(SANDBOXED_HOST_IO_NETWORK_TIMEOUT))
            .map_err(|err| HostIoError::Io {
                detail: format!("set read timeout {endpoint}: {err}"),
            })?;
        stream
            .set_write_timeout(Some(SANDBOXED_HOST_IO_NETWORK_TIMEOUT))
            .map_err(|err| HostIoError::Io {
                detail: format!("set write timeout {endpoint}: {err}"),
            })?;
        Ok(stream)
    }

    fn network_send(&self, endpoint: &str, payload: &[u8]) -> HostIoOutcome {
        if u64::try_from(payload.len()).unwrap_or(u64::MAX) > self.max_bytes {
            return Err(HostIoError::Io {
                detail: format!(
                    "network send of {} bytes to {endpoint} exceeds the {}-byte cap",
                    payload.len(),
                    self.max_bytes
                ),
            });
        }
        let mut stream = self.connect(endpoint)?;
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

    fn network_recv(&self, endpoint: &str, max_len: u64) -> HostIoOutcome {
        // Bound the read by the smaller of the caller-requested length and the
        // provider's per-operation cap.
        let cap = max_len.min(self.max_bytes);
        let stream = self.connect(endpoint)?;
        let mut bytes = Vec::new();
        // Bounded read: cap+1 so a peer that streams more than the cap fails
        // closed rather than being silently truncated.
        stream
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
        Ok(HostIoResponse::NetworkRecv { bytes })
    }

    /// A single-socket request/response round trip: connect once, write the
    /// framed `payload`, flush, then read the reply back on the *same* socket
    /// (bounded by `min(max_len, max_bytes)`). This is the mechanism behind a
    /// guest `http.get`/`fetch`: the response bytes returned here are the real
    /// status line + headers + body the peer sent, which the engine parses into a
    /// JS response object. Read termination relies on the peer closing the
    /// connection after responding (the engine frames `Connection: close`), so
    /// `read_to_end` returns at EOF rather than blocking until the read timeout.
    fn network_request(
        &self,
        endpoint: &str,
        payload: &[u8],
        max_len: u64,
        use_tls: bool,
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
            return self.network_request_tls(endpoint, payload, cap);
        }
        let mut stream = self.connect(endpoint)?;
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
        // Read the reply on the SAME socket. cap+1 so a peer that streams more
        // than the cap fails closed rather than being silently truncated.
        let mut response = Vec::new();
        stream
            .take(cap.saturating_add(1))
            .read_to_end(&mut response)
            .map_err(|err| HostIoError::Io {
                detail: format!("recv from {endpoint}: {err}"),
            })?;
        if u64::try_from(response.len()).unwrap_or(u64::MAX) > cap {
            return Err(HostIoError::Io {
                detail: format!("network response from {endpoint} exceeds the {cap}-byte cap"),
            });
        }
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
    /// builder), and the read tolerates a peer that closes without a TLS
    /// `close_notify` after responding (common for one-shot HTTP servers).
    fn network_request_tls(&self, endpoint: &str, payload: &[u8], cap: u64) -> HostIoOutcome {
        // Verification identity: the host part of `host:port`. (IPv6 endpoints
        // in bracket form are not produced by the engine's wire builder.)
        let host = endpoint.rsplit_once(':').map_or(endpoint, |(h, _)| h);
        let server_name =
            rustls_pki_types::ServerName::try_from(host.to_string()).map_err(|err| {
                HostIoError::Io {
                    detail: format!("invalid TLS server name {host}: {err}"),
                }
            })?;
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
        let stream = self.connect(endpoint)?;
        let mut tls = rustls::StreamOwned::new(conn, stream);
        tls.write_all(payload).map_err(|err| HostIoError::Io {
            detail: format!("TLS send to {endpoint}: {err}"),
        })?;
        tls.flush().map_err(|err| HostIoError::Io {
            detail: format!("TLS flush to {endpoint}: {err}"),
        })?;
        // Bounded read of the reply on the same TLS session. cap+1 semantics as
        // the plaintext path: a peer that streams more than the cap fails closed
        // rather than being silently truncated. `UnexpectedEof` after the
        // response is a peer that TCP-closed without `close_notify`; the HTTP
        // framing (`Connection: close`) already delimits the response, so treat
        // it as end-of-stream rather than an error.
        let mut response = Vec::new();
        let mut buf = [0u8; 8192];
        loop {
            if u64::try_from(response.len()).unwrap_or(u64::MAX) > cap {
                return Err(HostIoError::Io {
                    detail: format!("network response from {endpoint} exceeds the {cap}-byte cap"),
                });
            }
            match tls.read(&mut buf) {
                Ok(0) => break,
                Ok(n) => response.extend_from_slice(&buf[..n]),
                Err(err) if err.kind() == std::io::ErrorKind::UnexpectedEof => break,
                Err(err) => {
                    return Err(HostIoError::Io {
                        detail: format!("TLS recv from {endpoint}: {err}"),
                    });
                }
            }
        }
        if u64::try_from(response.len()).unwrap_or(u64::MAX) > cap {
            return Err(HostIoError::Io {
                detail: format!("network response from {endpoint} exceeds the {cap}-byte cap"),
            });
        }
        Ok(HostIoResponse::NetworkRequest { response })
    }
}

impl HostIoProvider for SandboxedHostIo {
    fn name(&self) -> &str {
        "sandboxed-host-io"
    }

    fn perform(&self, request: &HostIoRequest, granted: &[HostIoCapability]) -> HostIoOutcome {
        let required = request.required_capability();
        if !capability_granted(granted, required) {
            return Err(HostIoError::CapabilityMissing {
                capability: required,
            });
        }
        match request {
            HostIoRequest::FsRead { path } => self.fs_read(path),
            HostIoRequest::FsWrite { path, data } => self.fs_write(path, data),
            HostIoRequest::FsMeta {
                operation,
                path,
                arguments,
                data,
            } => self.fs_meta(*operation, path, arguments, data),
            HostIoRequest::NetworkSend { endpoint, payload } => {
                self.network_send(endpoint, payload)
            }
            HostIoRequest::NetworkRecv { endpoint, max_len } => {
                self.network_recv(endpoint, *max_len)
            }
            HostIoRequest::NetworkRequest {
                endpoint,
                payload,
                max_len,
                use_tls,
            } => self.network_request(endpoint, payload, *max_len, *use_tls),
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
mod tests {
    use super::*;

    fn all_requests() -> Vec<HostIoRequest> {
        vec![
            HostIoRequest::FsRead {
                path: "a.txt".to_string(),
            },
            HostIoRequest::FsWrite {
                path: "a.txt".to_string(),
                data: vec![1, 2, 3],
            },
            HostIoRequest::FsMeta {
                operation: FsOperation::Stat,
                path: "a.txt".to_string(),
                arguments: Vec::new(),
                data: Vec::new(),
            },
            HostIoRequest::NetworkSend {
                endpoint: "example.com:443".to_string(),
                payload: vec![4, 5],
            },
            HostIoRequest::NetworkRecv {
                endpoint: "example.com:443".to_string(),
                max_len: 1024,
            },
        ]
    }

    #[test]
    fn deny_all_denies_every_request_kind() {
        let provider = DenyAllHostIo;
        for request in all_requests() {
            let granted = [request.required_capability()];
            let outcome = provider.perform(&request, &granted);
            assert!(
                matches!(outcome, Err(HostIoError::Denied { .. })),
                "deny-all must deny {}",
                request.kind()
            );
        }
    }

    #[test]
    fn required_capability_mapping_is_exact() {
        assert_eq!(
            HostIoRequest::FsRead {
                path: String::new()
            }
            .required_capability(),
            HostIoCapability::FsRead
        );
        assert_eq!(
            HostIoRequest::FsWrite {
                path: String::new(),
                data: Vec::new()
            }
            .required_capability(),
            HostIoCapability::FsWrite
        );
        assert_eq!(
            HostIoRequest::FsMeta {
                operation: FsOperation::Stat,
                path: String::new(),
                arguments: Vec::new(),
                data: Vec::new(),
            }
            .required_capability(),
            HostIoCapability::FsRead
        );
        assert_eq!(
            HostIoRequest::FsMeta {
                operation: FsOperation::Remove,
                path: String::new(),
                arguments: Vec::new(),
                data: Vec::new(),
            }
            .required_capability(),
            HostIoCapability::FsWrite
        );
        assert_eq!(
            HostIoRequest::NetworkSend {
                endpoint: String::new(),
                payload: Vec::new()
            }
            .required_capability(),
            HostIoCapability::NetworkSend
        );
        assert_eq!(
            HostIoRequest::NetworkRecv {
                endpoint: String::new(),
                max_len: 0
            }
            .required_capability(),
            HostIoCapability::NetworkRecv
        );
    }

    #[test]
    fn serde_round_trips_requests_responses_and_errors() {
        for request in all_requests() {
            let json = serde_json::to_string(&request).expect("serialize request");
            let back: HostIoRequest = serde_json::from_str(&json).expect("deserialize request");
            assert_eq!(request, back);
        }

        let response = HostIoResponse::FsRead {
            bytes: b"abc".to_vec(),
        };
        let json = serde_json::to_string(&response).expect("serialize response");
        assert_eq!(
            response,
            serde_json::from_str::<HostIoResponse>(&json).expect("deserialize response")
        );

        let response = HostIoResponse::FsMeta {
            result: FsMetaResult::Metadata(FsMetadata {
                size: 3,
                mode: 0o100600,
                modified_millis: 1_000,
                is_file: true,
                is_directory: false,
                is_symbolic_link: false,
            }),
        };
        let json = serde_json::to_string(&response).expect("serialize fs meta response");
        assert_eq!(
            response,
            serde_json::from_str::<HostIoResponse>(&json).expect("deserialize fs meta response")
        );

        let error = HostIoError::CapabilityMissing {
            capability: HostIoCapability::FsRead,
        };
        let json = serde_json::to_string(&error).expect("serialize error");
        assert_eq!(
            error,
            serde_json::from_str::<HostIoError>(&json).expect("deserialize error")
        );

        let error = HostIoError::Fs {
            code: "ENOENT".to_string(),
            detail: "missing".to_string(),
        };
        let json = serde_json::to_string(&error).expect("serialize fs error");
        assert_eq!(
            error,
            serde_json::from_str::<HostIoError>(&json).expect("deserialize fs error")
        );
    }

    #[test]
    fn capability_granted_membership() {
        let granted = [HostIoCapability::FsRead, HostIoCapability::NetworkRecv];
        assert!(capability_granted(&granted, HostIoCapability::FsRead));
        assert!(capability_granted(&granted, HostIoCapability::NetworkRecv));
        assert!(!capability_granted(&granted, HostIoCapability::FsWrite));
        assert!(!capability_granted(&[], HostIoCapability::FsRead));
    }

    #[test]
    fn recording_transcript_captures_in_order() {
        let recorder = InMemoryHostIoTranscript::recording();
        let request = HostIoRequest::FsRead {
            path: "a.txt".to_string(),
        };
        assert!(recorder.replay(&request).is_none());
        recorder.record(&request, &Ok(HostIoResponse::FsRead { bytes: vec![1, 2] }));
        assert_eq!(recorder.len(), 1);
        assert!(!recorder.is_empty());
    }

    #[test]
    fn replaying_returns_recorded_outcomes_in_order() {
        let entries = vec![
            (
                HostIoRequest::FsRead {
                    path: "a.txt".to_string(),
                },
                Ok(HostIoResponse::FsRead {
                    bytes: b"recorded".to_vec(),
                }),
            ),
            (
                HostIoRequest::FsWrite {
                    path: "a.txt".to_string(),
                    data: vec![1, 2, 3],
                },
                Ok(HostIoResponse::FsWrite { bytes_written: 3 }),
            ),
        ];
        let replay = InMemoryHostIoTranscript::replaying(entries);
        assert_eq!(replay.mode(), HostIoReplayMode::Replay);
        replay.begin_execution().expect("begin replay");
        let first = replay
            .replay(&HostIoRequest::FsRead {
                path: "a.txt".to_string(),
            })
            .expect("first replay");
        assert_eq!(
            first,
            Ok(HostIoResponse::FsRead {
                bytes: b"recorded".to_vec()
            })
        );
        let second = replay
            .replay(&HostIoRequest::FsWrite {
                path: "a.txt".to_string(),
                data: vec![1, 2, 3],
            })
            .expect("second replay");
        assert_eq!(second, Ok(HostIoResponse::FsWrite { bytes_written: 3 }));
        assert_eq!(replay.finish_execution().unwrap(), replay.entries());
        assert!(replay.finish_execution().is_err());
    }

    #[test]
    fn replay_finish_rejects_and_poisons_an_unused_suffix() {
        let first_request = HostIoRequest::FsRead {
            path: "first.txt".to_string(),
        };
        let second_request = HostIoRequest::FsWrite {
            path: "second.txt".to_string(),
            data: vec![2],
        };
        let replay = InMemoryHostIoTranscript::replaying(vec![
            (
                first_request.clone(),
                Ok(HostIoResponse::FsRead { bytes: vec![1] }),
            ),
            (
                second_request.clone(),
                Ok(HostIoResponse::FsWrite { bytes_written: 1 }),
            ),
        ]);

        replay.begin_execution().expect("begin replay");
        assert!(matches!(replay.replay(&first_request), Some(Ok(_))));
        let error = replay
            .finish_execution()
            .expect_err("unused replay suffix must fail finalization");
        assert!(matches!(
            &error,
            HostIoError::Denied { reason }
                if reason.contains("1 unused transcript entries starting at index 1")
        ));
        assert_eq!(
            replay
                .replay(&second_request)
                .expect("poisoned replay outcome"),
            Err(error.clone()),
            "finalization is terminal and must not permit suffix consumption"
        );
        assert_eq!(replay.finish_execution(), Err(error));
    }

    #[test]
    fn replay_mismatch_never_advances_and_permanently_prevents_resynchronization() {
        let expected_first = HostIoRequest::FsRead {
            path: "first.txt".to_string(),
        };
        let expected_second = HostIoRequest::FsWrite {
            path: "second.txt".to_string(),
            data: vec![2],
        };
        let replay = InMemoryHostIoTranscript::replaying(vec![
            (
                expected_first.clone(),
                Ok(HostIoResponse::FsRead { bytes: vec![1] }),
            ),
            (
                expected_second.clone(),
                Ok(HostIoResponse::FsWrite { bytes_written: 1 }),
            ),
        ]);

        replay.begin_execution().expect("begin replay");
        let mismatch = replay
            .replay(&HostIoRequest::FsWrite {
                path: "wrong.txt".to_string(),
                data: vec![],
            })
            .expect("mismatch outcome")
            .expect_err("mismatch must fail closed");
        assert!(matches!(&mismatch, HostIoError::SandboxViolation { .. }));
        assert!(matches!(
            &*replay
                .execution_state
                .lock()
                .expect("host I/O execution state mutex"),
            HostIoExecutionState::Poisoned(_)
        ));

        for request in [&expected_first, &expected_second] {
            assert_eq!(
                replay.replay(request).expect("poisoned replay outcome"),
                Err(mismatch.clone()),
                "a later matching request must not resynchronize poisoned replay"
            );
        }
        assert_eq!(replay.finish_execution(), Err(mismatch));
    }

    #[test]
    fn replay_exhaustion_permanently_fails_closed() {
        let replay = InMemoryHostIoTranscript::replaying(Vec::new());
        let request = HostIoRequest::FsRead {
            path: "extra.txt".to_string(),
        };
        replay.begin_execution().expect("begin replay");
        let error = replay
            .replay(&request)
            .expect("exhaustion outcome")
            .expect_err("a request beyond the transcript must fail closed");
        assert!(matches!(&error, HostIoError::Denied { .. }));
        assert_eq!(replay.replay(&request), Some(Err(error.clone())));
        assert_eq!(replay.finish_execution(), Err(error));
    }

    #[derive(Debug)]
    struct ExplicitlyRejectingRecorder;

    impl HostIoRecorder for ExplicitlyRejectingRecorder {
        fn begin_execution(&self) -> Result<(), HostIoError> {
            Err(HostIoError::NotImplemented {
                what: "test recorder has no execution lifecycle".to_string(),
            })
        }

        fn replay(&self, _request: &HostIoRequest) -> Option<HostIoOutcome> {
            None
        }

        fn record(&self, _request: &HostIoRequest, _outcome: &HostIoOutcome) {}

        fn finish_execution(&self) -> Result<Vec<(HostIoRequest, HostIoOutcome)>, HostIoError> {
            Err(HostIoError::NotImplemented {
                what: "test recorder has no execution lifecycle".to_string(),
            })
        }
    }

    #[test]
    fn custom_recorder_must_explicitly_reject_unsupported_boundaries() {
        assert!(matches!(
            ExplicitlyRejectingRecorder.begin_execution(),
            Err(HostIoError::NotImplemented { .. })
        ));
        assert!(matches!(
            ExplicitlyRejectingRecorder.finish_execution(),
            Err(HostIoError::NotImplemented { .. })
        ));
    }

    #[test]
    fn recording_boundaries_return_only_the_current_execution() {
        let recorder = InMemoryHostIoTranscript::recording();
        let first = HostIoRequest::FsRead {
            path: "first.txt".to_string(),
        };
        let second = HostIoRequest::FsRead {
            path: "second.txt".to_string(),
        };

        recorder.begin_execution().expect("begin first recording");
        recorder.record(&first, &Ok(HostIoResponse::FsRead { bytes: vec![1] }));
        assert_eq!(recorder.finish_execution().unwrap().len(), 1);

        recorder.begin_execution().expect("begin second recording");
        recorder.record(&second, &Ok(HostIoResponse::FsRead { bytes: vec![2] }));
        let current = recorder.finish_execution().unwrap();
        assert_eq!(current.len(), 1);
        assert_eq!(current[0].0, second);
        assert_eq!(recorder.recorded_entries().len(), 2);
    }

    #[test]
    fn concurrent_recording_begin_is_rejected_without_poisoning_active_execution() {
        let recorder = InMemoryHostIoTranscript::recording();
        let request = HostIoRequest::FsRead {
            path: "active.txt".to_string(),
        };

        recorder.begin_execution().expect("begin active recording");
        assert!(matches!(
            recorder.begin_execution(),
            Err(HostIoError::Denied { reason }) if reason.contains("already active")
        ));
        recorder.record(
            &request,
            &Ok(HostIoResponse::FsRead {
                bytes: b"active".to_vec(),
            }),
        );
        let current = recorder
            .finish_execution()
            .expect("active execution remains valid");
        assert_eq!(current.len(), 1);
        assert_eq!(current[0].0, request);
    }

    #[test]
    fn exactly_finalized_replay_is_single_use() {
        let replay = InMemoryHostIoTranscript::replaying(Vec::new());
        replay.begin_execution().expect("begin replay");
        assert!(replay.finish_execution().unwrap().is_empty());
        assert!(replay.begin_execution().is_err());
        assert!(replay.finish_execution().is_err());
        assert!(matches!(
            replay.replay(&HostIoRequest::FsRead {
                path: "late.txt".to_string(),
            }),
            Some(Err(HostIoError::Denied { .. }))
        ));
    }

    /// Self-contained scratch directory (avoids a `tempfile` dev-dependency).
    struct ScratchDir {
        path: PathBuf,
    }

    impl ScratchDir {
        fn new() -> Self {
            use std::sync::atomic::{AtomicU64, Ordering};
            static SEQ: AtomicU64 = AtomicU64::new(0);
            let seq = SEQ.fetch_add(1, Ordering::Relaxed);
            let mut path = std::env::temp_dir();
            path.push(format!(
                "frankenengine_sandbox_hostio_{}_{seq}",
                std::process::id()
            ));
            std::fs::create_dir_all(&path).expect("create scratch dir");
            Self { path }
        }
    }

    impl Drop for ScratchDir {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.path);
        }
    }

    fn sandboxed_realpath(provider: &SandboxedHostIo, path: &str) -> Result<String, HostIoError> {
        match provider.perform(
            &HostIoRequest::FsMeta {
                operation: FsOperation::Realpath,
                path: path.to_string(),
                arguments: Vec::new(),
                data: Vec::new(),
            },
            &[HostIoCapability::FsRead],
        ) {
            Ok(HostIoResponse::FsMeta {
                result: FsMetaResult::String(path),
            }) => Ok(path),
            Ok(other) => panic!("realpath returned the wrong response shape: {other:?}"),
            Err(error) => Err(error),
        }
    }

    #[cfg(unix)]
    #[derive(Debug, Clone, Copy)]
    enum MutationRaceCase {
        Write,
        Append,
        Mkdir,
        MkdirRecursive,
        Symlink,
        Rename,
        CopyFile,
        Unlink,
        RemoveFile,
        RemoveRecursive,
        RemoveDir,
        Truncate,
        Chmod,
        Utimes,
        Mkdtemp,
    }

    #[cfg(unix)]
    impl MutationRaceCase {
        const ALL: [Self; 15] = [
            Self::Write,
            Self::Append,
            Self::Mkdir,
            Self::MkdirRecursive,
            Self::Symlink,
            Self::Rename,
            Self::CopyFile,
            Self::Unlink,
            Self::RemoveFile,
            Self::RemoveRecursive,
            Self::RemoveDir,
            Self::Truncate,
            Self::Chmod,
            Self::Utimes,
            Self::Mkdtemp,
        ];

        fn setup(self, parent: &Path) {
            use std::os::unix::fs::PermissionsExt;

            std::fs::create_dir_all(parent).expect("create race parent");
            match self {
                Self::Write | Self::Append | Self::Truncate | Self::Utimes => {
                    std::fs::write(parent.join("file.txt"), b"before").expect("seed file");
                }
                Self::Mkdir | Self::MkdirRecursive | Self::Mkdtemp => {}
                Self::Symlink => {
                    std::fs::write(parent.join("source.txt"), b"source").expect("seed link source");
                }
                Self::Rename => {
                    std::fs::write(parent.join("source.txt"), b"rename source")
                        .expect("seed rename source");
                }
                Self::CopyFile => {
                    std::fs::write(parent.join("source.txt"), b"copy source")
                        .expect("seed copy source");
                    std::fs::write(parent.join("destination.txt"), b"copy destination")
                        .expect("seed copy destination");
                }
                Self::Unlink | Self::RemoveFile => {
                    std::fs::write(parent.join("remove.txt"), b"remove me")
                        .expect("seed removed file");
                }
                Self::RemoveRecursive => {
                    std::fs::create_dir_all(parent.join("remove-dir").join("nested"))
                        .expect("seed recursive directory");
                    std::fs::write(
                        parent.join("remove-dir").join("nested").join("file.txt"),
                        b"remove tree",
                    )
                    .expect("seed recursive file");
                }
                Self::RemoveDir => {
                    std::fs::create_dir(parent.join("empty-dir")).expect("seed empty directory");
                }
                Self::Chmod => {
                    let path = parent.join("file.txt");
                    std::fs::write(&path, b"chmod").expect("seed chmod file");
                    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600))
                        .expect("seed chmod mode");
                }
            }
        }

        fn trigger_on_resolution(self) -> usize {
            match self {
                Self::Rename | Self::CopyFile => 2,
                _ => 1,
            }
        }

        fn request(self) -> HostIoRequest {
            let fs_meta =
                |operation, path: &str, arguments: &[&str], data: &[u8]| HostIoRequest::FsMeta {
                    operation,
                    path: path.to_string(),
                    arguments: arguments.iter().map(|value| (*value).to_string()).collect(),
                    data: data.to_vec(),
                };
            match self {
                Self::Write => HostIoRequest::FsWrite {
                    path: "slot/file.txt".to_string(),
                    data: b"after".to_vec(),
                },
                Self::Append => fs_meta(FsOperation::Append, "slot/file.txt", &[], b"-after"),
                Self::Mkdir => fs_meta(FsOperation::Mkdir, "slot/new-dir", &[], &[]),
                Self::MkdirRecursive => fs_meta(
                    FsOperation::Mkdir,
                    "slot/new-parent/new-dir",
                    &["recursive=true"],
                    &[],
                ),
                Self::Symlink => fs_meta(FsOperation::Symlink, "source.txt", &["slot/link"], &[]),
                Self::Rename => fs_meta(
                    FsOperation::Rename,
                    "slot/source.txt",
                    &["slot/destination.txt"],
                    &[],
                ),
                Self::CopyFile => fs_meta(
                    FsOperation::CopyFile,
                    "slot/source.txt",
                    &["slot/destination.txt"],
                    &[],
                ),
                Self::Unlink => fs_meta(FsOperation::Unlink, "slot/remove.txt", &[], &[]),
                Self::RemoveFile => fs_meta(FsOperation::Remove, "slot/remove.txt", &[], &[]),
                Self::RemoveRecursive => fs_meta(
                    FsOperation::Remove,
                    "slot/remove-dir",
                    &["recursive=true"],
                    &[],
                ),
                Self::RemoveDir => fs_meta(FsOperation::RemoveDir, "slot/empty-dir", &[], &[]),
                Self::Truncate => fs_meta(FsOperation::Truncate, "slot/file.txt", &["2"], &[]),
                Self::Chmod => fs_meta(FsOperation::Chmod, "slot/file.txt", &["416"], &[]),
                Self::Utimes => fs_meta(FsOperation::Utimes, "slot/file.txt", &["1000"], &[]),
                Self::Mkdtemp => fs_meta(FsOperation::Mkdtemp, "slot/tmp-", &[], &[]),
            }
        }

        fn raced_final(self, root: &Path) -> PathBuf {
            let relative = match self {
                Self::Write | Self::Append | Self::Truncate | Self::Chmod | Self::Utimes => {
                    "slot/file.txt"
                }
                Self::Mkdir => "slot/new-dir",
                Self::MkdirRecursive => "slot/new-parent/new-dir",
                Self::Symlink => "slot/link",
                Self::Rename | Self::CopyFile => "slot/destination.txt",
                Self::Unlink | Self::RemoveFile => "slot/remove.txt",
                Self::RemoveRecursive => "slot/remove-dir",
                Self::RemoveDir => "slot/empty-dir",
                Self::Mkdtemp => "slot/tmp-000000",
            };
            root.join(relative)
        }

        fn assert_anchored_effect(self, anchored: &Path) {
            use std::os::unix::fs::{MetadataExt, PermissionsExt};

            match self {
                Self::Write => {
                    assert_eq!(std::fs::read(anchored.join("file.txt")).unwrap(), b"after");
                }
                Self::Append => {
                    assert_eq!(
                        std::fs::read(anchored.join("file.txt")).unwrap(),
                        b"before-after"
                    );
                }
                Self::Mkdir => assert!(anchored.join("new-dir").is_dir()),
                Self::MkdirRecursive => {
                    assert!(anchored.join("new-parent").join("new-dir").is_dir());
                }
                Self::Symlink => {
                    assert_eq!(
                        std::fs::read_link(anchored.join("link")).unwrap(),
                        PathBuf::from("source.txt")
                    );
                }
                Self::Rename => {
                    assert!(!anchored.join("source.txt").exists());
                    assert_eq!(
                        std::fs::read(anchored.join("destination.txt")).unwrap(),
                        b"rename source"
                    );
                }
                Self::CopyFile => {
                    assert_eq!(
                        std::fs::read(anchored.join("source.txt")).unwrap(),
                        b"copy source"
                    );
                    assert_eq!(
                        std::fs::read(anchored.join("destination.txt")).unwrap(),
                        b"copy source"
                    );
                }
                Self::Unlink | Self::RemoveFile => {
                    assert!(!anchored.join("remove.txt").exists());
                }
                Self::RemoveRecursive => assert!(!anchored.join("remove-dir").exists()),
                Self::RemoveDir => assert!(!anchored.join("empty-dir").exists()),
                Self::Truncate => {
                    assert_eq!(std::fs::read(anchored.join("file.txt")).unwrap(), b"be");
                }
                Self::Chmod => {
                    let mode = std::fs::metadata(anchored.join("file.txt"))
                        .unwrap()
                        .permissions()
                        .mode();
                    assert_eq!(mode & 0o777, 0o640);
                }
                Self::Utimes => {
                    let metadata = std::fs::metadata(anchored.join("file.txt")).unwrap();
                    assert_eq!(metadata.mtime(), 1);
                }
                Self::Mkdtemp => assert!(anchored.join("tmp-000000").is_dir()),
            }
        }
    }

    #[cfg(unix)]
    #[derive(Debug, PartialEq, Eq)]
    struct TreeEntrySnapshot {
        relative: PathBuf,
        mode: u32,
        length: u64,
        modified_seconds: i64,
        modified_nanoseconds: i64,
        payload: Vec<u8>,
    }

    #[cfg(unix)]
    fn tree_snapshot(root: &Path) -> Vec<TreeEntrySnapshot> {
        fn visit(root: &Path, path: &Path, entries: &mut Vec<TreeEntrySnapshot>) {
            use std::os::unix::ffi::OsStrExt;
            use std::os::unix::fs::MetadataExt;

            let metadata = std::fs::symlink_metadata(path).expect("snapshot metadata");
            let relative = path.strip_prefix(root).expect("snapshot path under root");
            let payload = if metadata.file_type().is_symlink() {
                std::fs::read_link(path)
                    .expect("snapshot symlink")
                    .as_os_str()
                    .as_bytes()
                    .to_vec()
            } else if metadata.is_file() {
                std::fs::read(path).expect("snapshot file")
            } else {
                Vec::new()
            };
            entries.push(TreeEntrySnapshot {
                relative: relative.to_path_buf(),
                mode: metadata.mode(),
                length: metadata.len(),
                modified_seconds: metadata.mtime(),
                modified_nanoseconds: metadata.mtime_nsec(),
                payload,
            });
            if metadata.is_dir() {
                let mut children: Vec<_> = std::fs::read_dir(path)
                    .expect("snapshot directory")
                    .map(|entry| entry.expect("snapshot directory entry").path())
                    .collect();
                children.sort();
                for child in children {
                    visit(root, &child, entries);
                }
            }
        }

        let mut entries = Vec::new();
        visit(root, root, &mut entries);
        entries
    }

    #[cfg(unix)]
    #[test]
    fn bd_wyff0_all_mutations_stay_on_anchored_parent_after_intermediate_swap() {
        for case in MutationRaceCase::ALL {
            let scratch = ScratchDir::new();
            let outside = ScratchDir::new();
            let provider = SandboxedHostIo::with_root(&scratch.path).expect("provider");
            let slot = provider.root().join("slot");
            let anchored = provider.root().join("anchored");
            case.setup(&slot);
            case.setup(&outside.path);
            let outside_before = tree_snapshot(&outside.path);

            let hook = ResolutionRaceHook::new(case.trigger_on_resolution());
            let worker_provider = provider
                .clone()
                .with_mutation_race_hook(std::sync::Arc::clone(&hook));
            let request = case.request();
            let worker = std::thread::spawn(move || {
                worker_provider.perform(&request, &[HostIoCapability::FsWrite])
            });

            hook.wait_until_resolved();
            std::fs::rename(&slot, &anchored).expect("rename resolved parent");
            std::os::unix::fs::symlink(&outside.path, &slot)
                .expect("replace parent with outside symlink");
            hook.resume();

            let outcome = worker.join().expect("mutation worker");
            assert!(
                outcome.is_ok(),
                "{case:?} failed after parent swap: {outcome:?}"
            );
            case.assert_anchored_effect(&anchored);
            assert_eq!(
                tree_snapshot(&outside.path),
                outside_before,
                "{case:?} mutated the outside tree after an intermediate swap"
            );
        }
    }

    #[cfg(unix)]
    #[test]
    fn bd_wyff0_all_mutations_refuse_or_unlink_final_symlink_without_following_it() {
        for case in MutationRaceCase::ALL {
            let scratch = ScratchDir::new();
            let outside = ScratchDir::new();
            let provider = SandboxedHostIo::with_root(&scratch.path).expect("provider");
            let slot = provider.root().join("slot");
            case.setup(&slot);
            case.setup(&outside.path);
            let outside_target = outside.path.join("outside-target");
            std::fs::write(&outside_target, b"must remain unchanged").expect("seed outside target");
            let outside_before = tree_snapshot(&outside.path);

            let hook = ResolutionRaceHook::new(case.trigger_on_resolution());
            let worker_provider = provider
                .clone()
                .with_mutation_race_hook(std::sync::Arc::clone(&hook));
            let request = case.request();
            let worker = std::thread::spawn(move || {
                worker_provider.perform(&request, &[HostIoCapability::FsWrite])
            });

            hook.wait_until_resolved();
            let raced_final = case.raced_final(provider.root());
            if std::fs::symlink_metadata(&raced_final).is_ok() {
                let mut saved = raced_final.as_os_str().to_owned();
                saved.push(".before-race");
                std::fs::rename(&raced_final, PathBuf::from(saved))
                    .expect("save original final entry");
            }
            std::os::unix::fs::symlink(&outside_target, &raced_final)
                .expect("install final outside symlink");
            hook.resume();

            let _outcome = worker.join().expect("mutation worker");
            assert_eq!(
                tree_snapshot(&outside.path),
                outside_before,
                "{case:?} followed a raced final symlink outside the sandbox"
            );
        }
    }

    /// Read-class operations under adversarial rename/symlink races (bd-8ju8m).
    #[cfg(unix)]
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    enum ReadRaceCase {
        Read,
        Exists,
        ReadDir,
        Stat,
        Lstat,
        ReadLink,
        Access,
        Realpath,
    }

    #[cfg(unix)]
    impl ReadRaceCase {
        const ALL: [Self; 8] = [
            Self::Read,
            Self::Exists,
            Self::ReadDir,
            Self::Stat,
            Self::Lstat,
            Self::ReadLink,
            Self::Access,
            Self::Realpath,
        ];

        fn guest_path(self) -> &'static str {
            match self {
                Self::ReadDir => "dir/sub",
                Self::Lstat | Self::ReadLink => "dir/sub/link",
                _ => "dir/sub/target.txt",
            }
        }

        fn request(self) -> HostIoRequest {
            match self {
                Self::Read => HostIoRequest::FsRead {
                    path: self.guest_path().to_string(),
                },
                Self::Exists => Self::meta_request(FsOperation::Exists, self.guest_path()),
                Self::ReadDir => Self::meta_request(FsOperation::ReadDir, self.guest_path()),
                Self::Stat => Self::meta_request(FsOperation::Stat, self.guest_path()),
                Self::Lstat => Self::meta_request(FsOperation::Lstat, self.guest_path()),
                Self::ReadLink => Self::meta_request(FsOperation::ReadLink, self.guest_path()),
                Self::Access => Self::meta_request(FsOperation::Access, self.guest_path()),
                Self::Realpath => Self::meta_request(FsOperation::Realpath, self.guest_path()),
            }
        }

        fn meta_request(operation: FsOperation, path: &str) -> HostIoRequest {
            HostIoRequest::FsMeta {
                operation,
                path: path.to_string(),
                arguments: Vec::new(),
                data: Vec::new(),
            }
        }

        /// Physical path of the entry an attacker swaps after resolution.
        fn raced_final(self, root: &Path) -> PathBuf {
            root.join(self.guest_path())
        }
    }

    #[cfg(unix)]
    const READ_RACE_INSIDE_BYTES: &[u8] = b"inside bytes";
    #[cfg(unix)]
    const READ_RACE_OUTSIDE_BYTES: &[u8] = b"OUTSIDE SECRET CONTENTS!";

    /// Seed the in-sandbox tree `dir/sub/{target.txt, link->target.txt}` and an
    /// attacker-controlled outside tree with the same entry names plus a marker.
    #[cfg(unix)]
    fn read_race_setup(provider: &SandboxedHostIo, outside: &Path) {
        let sub = provider.root().join("dir").join("sub");
        std::fs::create_dir_all(&sub).expect("create inside tree");
        std::fs::write(sub.join("target.txt"), READ_RACE_INSIDE_BYTES).expect("seed inside file");
        std::os::unix::fs::symlink("target.txt", sub.join("link")).expect("seed inside link");

        let outside_sub = outside.join("sub");
        std::fs::create_dir_all(&outside_sub).expect("create outside tree");
        std::fs::write(outside_sub.join("target.txt"), READ_RACE_OUTSIDE_BYTES)
            .expect("seed outside file");
        std::os::unix::fs::symlink("outside-target", outside_sub.join("link"))
            .expect("seed outside link");
        std::fs::write(outside_sub.join("outside-marker"), READ_RACE_OUTSIDE_BYTES)
            .expect("seed outside marker");
    }

    /// After resolution completes, an attacker renames the first path component
    /// away and drops a symlink to an outside tree in its place. Every read
    /// must keep operating on the descriptors it resolved and observe only the
    /// original in-sandbox bytes and metadata.
    #[cfg(unix)]
    #[test]
    fn bd_8ju8m_all_reads_stay_on_resolved_descriptors_after_intermediate_swap() {
        for case in ReadRaceCase::ALL {
            let scratch = ScratchDir::new();
            let outside = ScratchDir::new();
            let provider = SandboxedHostIo::with_root(&scratch.path).expect("provider");
            read_race_setup(&provider, &outside.path);

            let hook = ResolutionRaceHook::new(1);
            let worker_provider = provider
                .clone()
                .with_read_race_hook(std::sync::Arc::clone(&hook));
            let request = case.request();
            let worker = std::thread::spawn(move || {
                worker_provider.perform(&request, &[HostIoCapability::FsRead])
            });

            hook.wait_until_resolved();
            std::fs::rename(provider.root().join("dir"), provider.root().join("moved"))
                .expect("rename resolved intermediate directory");
            std::os::unix::fs::symlink(outside.path.join("sub"), provider.root().join("dir"))
                .expect("replace intermediate directory with outside symlink");
            hook.resume();

            let outcome = worker.join().expect("read worker");
            match case {
                ReadRaceCase::Read => assert_eq!(
                    outcome,
                    Ok(HostIoResponse::FsRead {
                        bytes: READ_RACE_INSIDE_BYTES.to_vec(),
                    }),
                    "{case:?} must read the resolved in-sandbox file"
                ),
                ReadRaceCase::Exists => assert_eq!(
                    outcome,
                    Ok(HostIoResponse::FsMeta {
                        result: FsMetaResult::Bool(true),
                    })
                ),
                ReadRaceCase::ReadDir => {
                    let Ok(HostIoResponse::FsMeta {
                        result: FsMetaResult::Strings(mut names),
                    }) = outcome
                    else {
                        panic!("{case:?} unexpected outcome after intermediate swap");
                    };
                    names.sort();
                    assert_eq!(
                        names,
                        vec!["link".to_string(), "target.txt".to_string()],
                        "{case:?} must list the resolved in-sandbox directory only"
                    );
                }
                ReadRaceCase::Stat => {
                    let Ok(HostIoResponse::FsMeta {
                        result: FsMetaResult::Metadata(metadata),
                    }) = outcome
                    else {
                        panic!("{case:?} unexpected outcome after intermediate swap");
                    };
                    assert!(metadata.is_file);
                    assert_eq!(
                        metadata.size,
                        READ_RACE_INSIDE_BYTES.len() as u64,
                        "{case:?} must report in-sandbox metadata"
                    );
                }
                ReadRaceCase::Lstat => {
                    let Ok(HostIoResponse::FsMeta {
                        result: FsMetaResult::Metadata(metadata),
                    }) = outcome
                    else {
                        panic!("{case:?} unexpected outcome after intermediate swap");
                    };
                    assert!(metadata.is_symbolic_link);
                    assert_eq!(
                        metadata.size,
                        "target.txt".len() as u64,
                        "{case:?} must report the resolved in-sandbox link"
                    );
                }
                ReadRaceCase::ReadLink => assert_eq!(
                    outcome,
                    Ok(HostIoResponse::FsMeta {
                        result: FsMetaResult::String("target.txt".to_string()),
                    })
                ),
                ReadRaceCase::Access => assert_eq!(
                    outcome,
                    Ok(HostIoResponse::FsMeta {
                        result: FsMetaResult::Unit,
                    })
                ),
                ReadRaceCase::Realpath => assert_eq!(
                    outcome,
                    Ok(HostIoResponse::FsMeta {
                        result: FsMetaResult::String("/dir/sub/target.txt".to_string()),
                    })
                ),
            }
        }
    }

    /// After resolution completes, an attacker swaps the final entry itself for
    /// a symlink pointing outside the sandbox. Reads that reopen the final
    /// entry must refuse to follow it; reads that already finished resolution
    /// must not consult the pathname again. No outside bytes or metadata may be
    /// observed in any case.
    #[cfg(unix)]
    #[test]
    fn bd_8ju8m_all_reads_refuse_final_symlink_swapped_after_resolution() {
        for case in ReadRaceCase::ALL {
            let scratch = ScratchDir::new();
            let outside = ScratchDir::new();
            let provider = SandboxedHostIo::with_root(&scratch.path).expect("provider");
            read_race_setup(&provider, &outside.path);
            let outside_secret = outside.path.join("sub").join("target.txt");

            let hook = ResolutionRaceHook::new(1);
            let worker_provider = provider
                .clone()
                .with_read_race_hook(std::sync::Arc::clone(&hook));
            let request = case.request();
            let worker = std::thread::spawn(move || {
                worker_provider.perform(&request, &[HostIoCapability::FsRead])
            });

            hook.wait_until_resolved();
            let raced_final = case.raced_final(provider.root());
            let mut saved = raced_final.as_os_str().to_owned();
            saved.push(".before-race");
            std::fs::rename(&raced_final, PathBuf::from(saved)).expect("save original entry");
            let swap_target: PathBuf = if case == ReadRaceCase::ReadDir {
                outside.path.join("sub")
            } else {
                outside_secret.clone()
            };
            std::os::unix::fs::symlink(&swap_target, &raced_final)
                .expect("install final outside symlink");
            hook.resume();

            let outcome = worker.join().expect("read worker");
            match case {
                ReadRaceCase::Read | ReadRaceCase::ReadDir => assert!(
                    matches!(outcome, Err(HostIoError::SandboxViolation { .. })),
                    "{case:?} must refuse a final symlink swapped in after resolution, got {outcome:?}"
                ),
                ReadRaceCase::Stat | ReadRaceCase::Lstat => {
                    let Ok(HostIoResponse::FsMeta {
                        result: FsMetaResult::Metadata(metadata),
                    }) = outcome
                    else {
                        panic!("{case:?} unexpected outcome after final swap: inspect for escape");
                    };
                    assert!(
                        metadata.is_symbolic_link,
                        "{case:?} must not follow the swapped-in symlink"
                    );
                    assert!(!metadata.is_file);
                }
                ReadRaceCase::ReadLink => {
                    // readlink never follows: it reports the attacker-authored
                    // link text, which discloses nothing the attacker did not
                    // already write.
                    let Ok(HostIoResponse::FsMeta {
                        result: FsMetaResult::String(reported),
                    }) = outcome
                    else {
                        panic!("{case:?} unexpected outcome after final swap");
                    };
                    assert_eq!(reported, outside_secret.to_string_lossy());
                }
                ReadRaceCase::Exists => assert_eq!(
                    outcome,
                    Ok(HostIoResponse::FsMeta {
                        result: FsMetaResult::Bool(true),
                    }),
                    "{case:?} answered from completed resolution, not the swapped pathname"
                ),
                ReadRaceCase::Access => assert_eq!(
                    outcome,
                    Ok(HostIoResponse::FsMeta {
                        result: FsMetaResult::Unit,
                    })
                ),
                ReadRaceCase::Realpath => assert_eq!(
                    outcome,
                    Ok(HostIoResponse::FsMeta {
                        result: FsMetaResult::String("/dir/sub/target.txt".to_string()),
                    }),
                    "{case:?} renders held-descriptor components, not the swapped pathname"
                ),
            }
        }
    }

    /// The bounded in-root follow loop preserves documented semantics: chains
    /// of in-root symlinks (including directory hops and absolute-inside-root
    /// targets) resolve, while cycles fail closed with ELOOP instead of
    /// spinning.
    #[cfg(unix)]
    #[test]
    fn bd_8ju8m_in_root_symlink_chains_resolve_and_cycles_fail_closed() {
        let scratch = ScratchDir::new();
        let provider = SandboxedHostIo::with_root(&scratch.path).expect("provider");
        std::fs::create_dir_all(provider.root().join("real")).expect("create real dir");
        std::fs::write(provider.root().join("real").join("data.txt"), b"chained")
            .expect("seed target");
        // hop -> real (directory symlink), alias -> hop/data.txt (via symlinked dir),
        // abs -> <root>/real/data.txt (absolute target back inside the root).
        std::os::unix::fs::symlink("real", provider.root().join("hop")).expect("dir link");
        std::os::unix::fs::symlink("hop/data.txt", provider.root().join("alias"))
            .expect("chained link");
        std::os::unix::fs::symlink(
            provider.root().join("real").join("data.txt"),
            provider.root().join("abs"),
        )
        .expect("absolute in-root link");

        for path in ["alias", "abs", "hop/data.txt"] {
            let read = provider
                .perform(
                    &HostIoRequest::FsRead {
                        path: path.to_string(),
                    },
                    &[HostIoCapability::FsRead],
                )
                .unwrap_or_else(|err| panic!("read through {path}: {err:?}"));
            assert_eq!(
                read,
                HostIoResponse::FsRead {
                    bytes: b"chained".to_vec(),
                }
            );
        }
        assert_eq!(
            sandboxed_realpath(&provider, "alias").expect("realpath through chain"),
            "/real/data.txt"
        );

        // A -> B -> A cycle must terminate with ELOOP, not hang or escape.
        std::os::unix::fs::symlink("cycle-b", provider.root().join("cycle-a")).expect("cycle a");
        std::os::unix::fs::symlink("cycle-a", provider.root().join("cycle-b")).expect("cycle b");
        assert!(
            matches!(
                provider.perform(
                    &HostIoRequest::FsRead {
                        path: "cycle-a".to_string(),
                    },
                    &[HostIoCapability::FsRead],
                ),
                Err(HostIoError::Fs { code, .. }) if code == "ELOOP"
            ),
            "symlink cycles must fail closed with ELOOP"
        );

        // An in-root symlink whose target climbs above the root must still be
        // rejected even though every component exists.
        std::os::unix::fs::symlink("../outside", provider.root().join("climb"))
            .expect("climbing link");
        assert!(matches!(
            provider.perform(
                &HostIoRequest::FsRead {
                    path: "climb".to_string(),
                },
                &[HostIoCapability::FsRead],
            ),
            Err(HostIoError::SandboxViolation { .. })
        ));
    }

    #[test]
    fn sandboxed_provider_name_is_stable() {
        let scratch = ScratchDir::new();
        let provider = SandboxedHostIo::with_root(&scratch.path).expect("provider");
        assert_eq!(provider.name(), "sandboxed-host-io");
    }

    #[test]
    fn sandboxed_round_trip_writes_and_reads_real_bytes() {
        let scratch = ScratchDir::new();
        let provider = SandboxedHostIo::with_root(&scratch.path).expect("provider");
        std::fs::create_dir_all(provider.root().join("sub").join("dir"))
            .expect("create explicit parent directories");
        let write = provider
            .perform(
                &HostIoRequest::FsWrite {
                    path: "sub/dir/data.txt".to_string(),
                    data: b"real bytes".to_vec(),
                },
                &[HostIoCapability::FsWrite],
            )
            .expect("write");
        assert_eq!(write, HostIoResponse::FsWrite { bytes_written: 10 });
        // The write really hit the disk under the canonical root.
        assert_eq!(
            std::fs::read(provider.root().join("sub").join("dir").join("data.txt")).expect("disk"),
            b"real bytes"
        );
        let read = provider
            .perform(
                &HostIoRequest::FsRead {
                    path: "sub/dir/data.txt".to_string(),
                },
                &[HostIoCapability::FsRead],
            )
            .expect("read");
        assert_eq!(
            read,
            HostIoResponse::FsRead {
                bytes: b"real bytes".to_vec()
            }
        );
    }

    #[test]
    fn bd_p5bsj_realpath_is_virtual_absolute_reusable_and_root_private() {
        let scratch = ScratchDir::new();
        let provider = SandboxedHostIo::with_root(&scratch.path).expect("provider");
        std::fs::create_dir_all(provider.root().join("nested")).expect("create nested directory");
        std::fs::write(
            provider.root().join("nested").join("data.txt"),
            b"guest bytes",
        )
        .expect("seed guest file");

        let guest_path =
            sandboxed_realpath(&provider, "nested/data.txt").expect("resolve guest path");
        assert_eq!(guest_path, "/nested/data.txt");
        assert!(
            !guest_path.contains(provider.root().to_str().expect("scratch root is UTF-8")),
            "realpath must not expose the physical sandbox root"
        );

        let reused = provider
            .perform(
                &HostIoRequest::FsRead { path: guest_path },
                &[HostIoCapability::FsRead],
            )
            .expect("reuse virtual absolute realpath result");
        assert_eq!(
            reused,
            HostIoResponse::FsRead {
                bytes: b"guest bytes".to_vec(),
            }
        );
    }

    #[test]
    fn bd_p5bsj_realpath_transcript_is_independent_of_physical_root() {
        let left_scratch = ScratchDir::new();
        let right_scratch = ScratchDir::new();
        let left = SandboxedHostIo::with_root(&left_scratch.path).expect("left provider");
        let right = SandboxedHostIo::with_root(&right_scratch.path).expect("right provider");
        assert_ne!(left.root(), right.root());
        for provider in [&left, &right] {
            std::fs::create_dir_all(provider.root().join("same")).expect("create same directory");
            std::fs::write(provider.root().join("same").join("file.txt"), b"same")
                .expect("seed same file");
        }
        let request = HostIoRequest::FsMeta {
            operation: FsOperation::Realpath,
            path: "same/file.txt".to_string(),
            arguments: Vec::new(),
            data: Vec::new(),
        };
        let capture = |provider: &SandboxedHostIo| {
            let transcript = InMemoryHostIoTranscript::recording();
            transcript.begin_execution().expect("begin recording");
            let outcome = provider.perform(&request, &[HostIoCapability::FsRead]);
            transcript.record(&request, &outcome);
            transcript.finish_execution().expect("finish recording")
        };

        let left_transcript = capture(&left);
        let right_transcript = capture(&right);
        assert_eq!(left_transcript, right_transcript);
        assert_eq!(
            left_transcript[0].1,
            Ok(HostIoResponse::FsMeta {
                result: FsMetaResult::String("/same/file.txt".to_string()),
            })
        );
    }

    #[cfg(unix)]
    #[test]
    fn bd_p5bsj_realpath_canonicalizes_symlink_aliases_in_guest_namespace() {
        let scratch = ScratchDir::new();
        let provider = SandboxedHostIo::with_root(&scratch.path).expect("provider");
        std::fs::create_dir_all(provider.root().join("actual")).expect("create actual directory");
        std::fs::write(provider.root().join("actual").join("target.txt"), b"target")
            .expect("seed target");
        std::os::unix::fs::symlink("actual/target.txt", provider.root().join("alias.txt"))
            .expect("create guest symlink alias");

        assert_eq!(
            sandboxed_realpath(&provider, "/alias.txt").expect("resolve alias"),
            "/actual/target.txt"
        );
    }

    #[test]
    fn bd_p5bsj_realpath_dot_and_virtual_slash_are_the_same_root() {
        let scratch = ScratchDir::new();
        let provider = SandboxedHostIo::with_root(&scratch.path).expect("provider");

        assert_eq!(sandboxed_realpath(&provider, ".").unwrap(), "/");
        assert_eq!(sandboxed_realpath(&provider, "/").unwrap(), "/");
    }

    #[test]
    fn bd_p5bsj_virtual_absolute_paths_never_select_the_host_root() {
        let scratch = ScratchDir::new();
        let provider = SandboxedHostIo::with_root(&scratch.path).expect("provider");
        std::fs::create_dir_all(provider.root().join("etc")).expect("create virtual etc");
        std::fs::write(
            provider.root().join("etc").join("passwd"),
            b"sandbox-only passwd",
        )
        .expect("seed virtual passwd");

        let read = provider
            .perform(
                &HostIoRequest::FsRead {
                    path: "/etc/passwd".to_string(),
                },
                &[HostIoCapability::FsRead],
            )
            .expect("read virtual absolute path");
        assert_eq!(
            read,
            HostIoResponse::FsRead {
                bytes: b"sandbox-only passwd".to_vec(),
            }
        );
        assert!(matches!(
            provider.perform(
                &HostIoRequest::FsRead {
                    path: "/../etc/passwd".to_string(),
                },
                &[HostIoCapability::FsRead],
            ),
            Err(HostIoError::SandboxViolation { .. })
        ));
    }

    #[cfg(unix)]
    #[test]
    fn bd_p5bsj_realpath_rejects_non_utf8_canonical_components() {
        use std::os::unix::ffi::OsStringExt;

        let scratch = ScratchDir::new();
        let provider = SandboxedHostIo::with_root(&scratch.path).expect("provider");
        let non_utf8_name =
            std::ffi::OsString::from_vec(vec![b'n', b'o', b'n', b'u', b't', b'f', 0xff]);
        std::fs::write(provider.root().join(&non_utf8_name), b"unrepresentable")
            .expect("seed non-UTF-8 target");
        std::os::unix::fs::symlink(&non_utf8_name, provider.root().join("alias"))
            .expect("create UTF-8 alias");

        assert!(matches!(
            sandboxed_realpath(&provider, "alias"),
            Err(HostIoError::Fs { code, detail })
                if code == "EINVAL" && detail.contains("non-UTF-8")
        ));
    }

    #[cfg(unix)]
    #[test]
    fn bd_p5bsj_realpath_rejects_components_outside_the_guest_path_grammar() {
        let scratch = ScratchDir::new();
        let provider = SandboxedHostIo::with_root(&scratch.path).expect("provider");
        std::fs::write(provider.root().join("actual\\name"), b"unrepresentable")
            .expect("seed backslash target");
        std::os::unix::fs::symlink("actual\\name", provider.root().join("alias"))
            .expect("create reusable alias");

        assert!(matches!(
            sandboxed_realpath(&provider, "alias"),
            Err(HostIoError::Fs { code, detail })
                if code == "EINVAL" && detail.contains("guest path grammar")
        ));
    }

    #[test]
    fn sandboxed_fs_meta_operations_are_typed_and_path_jailed() {
        let scratch = ScratchDir::new();
        let provider = SandboxedHostIo::with_root(&scratch.path).expect("provider");
        let write = [HostIoCapability::FsWrite];
        let read = [HostIoCapability::FsRead];

        provider
            .perform(
                &HostIoRequest::FsMeta {
                    operation: FsOperation::Mkdir,
                    path: "tree/leaf".to_string(),
                    arguments: vec!["recursive=true".to_string()],
                    data: Vec::new(),
                },
                &write,
            )
            .expect("recursive mkdir");
        provider
            .perform(
                &HostIoRequest::FsWrite {
                    path: "tree/leaf/data.txt".to_string(),
                    data: b"abc".to_vec(),
                },
                &write,
            )
            .expect("write under explicit parent");

        let stat = provider
            .perform(
                &HostIoRequest::FsMeta {
                    operation: FsOperation::Stat,
                    path: "tree/leaf/data.txt".to_string(),
                    arguments: Vec::new(),
                    data: Vec::new(),
                },
                &read,
            )
            .expect("stat");
        assert!(matches!(
            stat,
            HostIoResponse::FsMeta {
                result: FsMetaResult::Metadata(FsMetadata {
                    size: 3,
                    is_file: true,
                    ..
                })
            }
        ));

        let entries = provider
            .perform(
                &HostIoRequest::FsMeta {
                    operation: FsOperation::ReadDir,
                    path: "tree/leaf".to_string(),
                    arguments: vec!["with_file_types=true".to_string()],
                    data: Vec::new(),
                },
                &read,
            )
            .expect("readdir");
        assert_eq!(
            entries,
            HostIoResponse::FsMeta {
                result: FsMetaResult::DirEntries(vec![FsDirEntry {
                    name: "data.txt".to_string(),
                    is_file: true,
                    is_directory: false,
                    is_symbolic_link: false,
                }])
            }
        );

        let missing = provider.perform(
            &HostIoRequest::FsMeta {
                operation: FsOperation::Unlink,
                path: "missing.txt".to_string(),
                arguments: Vec::new(),
                data: Vec::new(),
            },
            &write,
        );
        assert!(matches!(
            missing,
            Err(HostIoError::Fs { ref code, .. }) if code == "ENOENT"
        ));

        let forced_missing = provider.perform(
            &HostIoRequest::FsMeta {
                operation: FsOperation::Remove,
                path: "still-missing.txt".to_string(),
                arguments: vec!["force=true".to_string()],
                data: Vec::new(),
            },
            &write,
        );
        assert_eq!(
            forced_missing,
            Ok(HostIoResponse::FsMeta {
                result: FsMetaResult::Unit
            })
        );

        let missing_parent = provider.perform(
            &HostIoRequest::FsWrite {
                path: "missing-parent/data.txt".to_string(),
                data: b"must not create parents".to_vec(),
            },
            &write,
        );
        assert!(matches!(
            missing_parent,
            Err(HostIoError::Fs { ref code, .. }) if code == "ENOENT"
        ));

        let escape = provider.perform(
            &HostIoRequest::FsMeta {
                operation: FsOperation::Stat,
                path: "../outside".to_string(),
                arguments: Vec::new(),
                data: Vec::new(),
            },
            &read,
        );
        assert!(matches!(escape, Err(HostIoError::SandboxViolation { .. })));
    }

    #[test]
    fn sandboxed_read_returns_real_preexisting_contents() {
        let scratch = ScratchDir::new();
        let provider = SandboxedHostIo::with_root(&scratch.path).expect("provider");
        std::fs::write(provider.root().join("seed.txt"), b"seeded on disk").expect("seed");
        let read = provider
            .perform(
                &HostIoRequest::FsRead {
                    path: "seed.txt".to_string(),
                },
                &[HostIoCapability::FsRead],
            )
            .expect("read");
        assert_eq!(
            read,
            HostIoResponse::FsRead {
                bytes: b"seeded on disk".to_vec()
            }
        );
    }

    #[test]
    fn sandboxed_missing_capability_fails_closed() {
        let scratch = ScratchDir::new();
        let provider = SandboxedHostIo::with_root(&scratch.path).expect("provider");
        std::fs::write(provider.root().join("readable.txt"), b"hi").expect("seed");
        let outcome = provider.perform(
            &HostIoRequest::FsRead {
                path: "readable.txt".to_string(),
            },
            &[], // no capability granted
        );
        assert!(
            matches!(
                outcome,
                Err(HostIoError::CapabilityMissing {
                    capability: HostIoCapability::FsRead
                })
            ),
            "missing capability must fail closed before any I/O, got {outcome:?}"
        );
    }

    #[test]
    fn sandboxed_traversal_and_degenerate_paths_are_rejected() {
        let scratch = ScratchDir::new();
        let provider = SandboxedHostIo::with_root(&scratch.path).expect("provider");
        for raw in [
            "../escape.txt",
            "a/../../escape.txt",
            "/../escape.txt",
            "with\0nul.txt",
            "back\\slash.txt",
            "",
        ] {
            let read = provider.perform(
                &HostIoRequest::FsRead {
                    path: raw.to_string(),
                },
                &[HostIoCapability::FsRead],
            );
            assert!(
                matches!(read, Err(HostIoError::SandboxViolation { .. })),
                "read {raw:?} must be a sandbox violation, got {read:?}"
            );
            let write = provider.perform(
                &HostIoRequest::FsWrite {
                    path: raw.to_string(),
                    data: b"x".to_vec(),
                },
                &[HostIoCapability::FsWrite],
            );
            assert!(
                matches!(write, Err(HostIoError::SandboxViolation { .. })),
                "write {raw:?} must be a sandbox violation, got {write:?}"
            );
        }
    }

    #[test]
    fn sandboxed_oversize_read_and_write_fail_closed() {
        let scratch = ScratchDir::new();
        let provider = SandboxedHostIo::with_root_and_limit(&scratch.path, 8).expect("provider");
        let write = provider.perform(
            &HostIoRequest::FsWrite {
                path: "big.bin".to_string(),
                data: vec![0u8; 9],
            },
            &[HostIoCapability::FsWrite],
        );
        assert!(
            matches!(write, Err(HostIoError::Io { .. })),
            "oversize write must fail closed, got {write:?}"
        );
        assert!(
            !provider.root().join("big.bin").exists(),
            "nothing must be written when the write is rejected"
        );
        // A file larger than the cap (e.g. one that grew on disk) fails the read.
        std::fs::write(provider.root().join("grew.bin"), vec![1u8; 9]).expect("seed oversize");
        let read = provider.perform(
            &HostIoRequest::FsRead {
                path: "grew.bin".to_string(),
            },
            &[HostIoCapability::FsRead],
        );
        assert!(
            matches!(read, Err(HostIoError::Io { .. })),
            "oversize read must fail closed, got {read:?}"
        );
    }

    #[test]
    fn sandboxed_network_send_delivers_real_bytes() {
        use std::net::TcpListener;
        let scratch = ScratchDir::new();
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind listener");
        let addr = listener.local_addr().expect("local addr");
        let server = std::thread::spawn(move || {
            let (mut sock, _) = listener.accept().expect("accept");
            let mut received = Vec::new();
            sock.read_to_end(&mut received).expect("server read");
            received
        });
        let provider = SandboxedHostIo::with_root(&scratch.path).expect("provider");
        let out = provider
            .perform(
                &HostIoRequest::NetworkSend {
                    endpoint: addr.to_string(),
                    payload: b"GET / HTTP/1.0\r\n\r\n".to_vec(),
                },
                &[HostIoCapability::NetworkSend],
            )
            .expect("network send");
        assert_eq!(out, HostIoResponse::NetworkSend { bytes_sent: 18 });
        // The bytes really crossed the socket to the listening server.
        let received = server.join().expect("server thread");
        assert_eq!(received, b"GET / HTTP/1.0\r\n\r\n");
    }

    #[test]
    fn sandboxed_network_recv_reads_real_bytes() {
        use std::net::TcpListener;
        let scratch = ScratchDir::new();
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind listener");
        let addr = listener.local_addr().expect("local addr");
        let server = std::thread::spawn(move || {
            let (mut sock, _) = listener.accept().expect("accept");
            sock.write_all(b"HTTP/1.0 200 OK\r\n\r\nbody")
                .expect("server write");
            // Drop `sock` to close the connection so the client's bounded
            // read_to_end sees EOF and returns.
        });
        let provider = SandboxedHostIo::with_root(&scratch.path).expect("provider");
        let out = provider
            .perform(
                &HostIoRequest::NetworkRecv {
                    endpoint: addr.to_string(),
                    max_len: 4096,
                },
                &[HostIoCapability::NetworkRecv],
            )
            .expect("network recv");
        assert_eq!(
            out,
            HostIoResponse::NetworkRecv {
                bytes: b"HTTP/1.0 200 OK\r\n\r\nbody".to_vec()
            }
        );
        server.join().expect("server thread");
    }

    /// bd-3894s slice (4): a `NetworkRequest` is a single-socket round trip — the
    /// request is written and the reply read back on the *same* connection. The
    /// server reads the (half-closed) request to EOF, then responds and closes; the
    /// client returns the full response bytes.
    #[test]
    fn sandboxed_network_request_round_trips_on_one_socket() {
        use std::net::TcpListener;
        let scratch = ScratchDir::new();
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind listener");
        let addr = listener.local_addr().expect("local addr");
        let server = std::thread::spawn(move || {
            let (mut sock, _) = listener.accept().expect("accept");
            // The client half-closes its write side after sending, so read_to_end
            // returns the full request at EOF (no request-framing parser needed).
            let mut request = Vec::new();
            sock.read_to_end(&mut request).expect("server read request");
            sock.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 4\r\n\r\nbody")
                .expect("server write response");
            // Dropping `sock` closes the connection so the client read terminates.
            request
        });
        let provider = SandboxedHostIo::with_root(&scratch.path).expect("provider");
        let out = provider
            .perform(
                &HostIoRequest::NetworkRequest {
                    endpoint: addr.to_string(),
                    payload: b"GET /x HTTP/1.1\r\nHost: h\r\nConnection: close\r\n\r\n".to_vec(),
                    max_len: 4096,
                    use_tls: false,
                },
                // The round trip is authorized by the egress (send) capability.
                &[HostIoCapability::NetworkSend],
            )
            .expect("network request");
        assert_eq!(
            out,
            HostIoResponse::NetworkRequest {
                response: b"HTTP/1.1 200 OK\r\nContent-Length: 4\r\n\r\nbody".to_vec()
            },
            "the round trip returns the peer's full response"
        );
        let request = server.join().expect("server thread");
        assert_eq!(
            request, b"GET /x HTTP/1.1\r\nHost: h\r\nConnection: close\r\n\r\n",
            "the request really crossed the socket"
        );
    }

    /// Stand up a one-shot HTTPS (rustls) server on a loopback port with a fresh
    /// self-signed certificate for `127.0.0.1`. Returns the listener address, the
    /// certificate PEM (the trust anchor a client must install), and a join
    /// handle yielding the decrypted request bytes the server observed (empty if
    /// the handshake never completed).
    fn spawn_tls_http_server(
        response: &'static [u8],
    ) -> (
        std::net::SocketAddr,
        String,
        std::thread::JoinHandle<Vec<u8>>,
    ) {
        use std::net::TcpListener;
        let certified = rcgen::generate_simple_self_signed(vec!["127.0.0.1".to_string()])
            .expect("generate self-signed certificate");
        let cert_pem = certified.cert.pem();
        let cert_der = certified.cert.der().clone();
        let key_der =
            rustls_pki_types::PrivateKeyDer::Pkcs8(certified.key_pair.serialize_der().into());
        let provider = std::sync::Arc::new(rustls::crypto::ring::default_provider());
        let config = rustls::ServerConfig::builder_with_provider(provider)
            .with_safe_default_protocol_versions()
            .expect("server protocol versions")
            .with_no_client_auth()
            .with_single_cert(vec![cert_der], key_der)
            .expect("server certificate");
        let config = std::sync::Arc::new(config);
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind TLS listener");
        let addr = listener.local_addr().expect("local addr");
        let server = std::thread::spawn(move || {
            let (tcp, _) = listener.accept().expect("accept");
            let conn = match rustls::ServerConnection::new(config) {
                Ok(conn) => conn,
                Err(_) => return Vec::new(),
            };
            let mut tls = rustls::StreamOwned::new(conn, tcp);
            // Read the request up to the header terminator (the test requests
            // are bodyless GETs). A client that aborts the handshake (untrusted
            // anchor) surfaces here as a read error: report an empty request.
            let mut request = Vec::new();
            let mut buf = [0u8; 1024];
            loop {
                match tls.read(&mut buf) {
                    Ok(0) => break,
                    Ok(n) => {
                        request.extend_from_slice(&buf[..n]);
                        if request.windows(4).any(|w| w == b"\r\n\r\n") {
                            break;
                        }
                    }
                    Err(_) => return Vec::new(),
                }
            }
            let _ = tls.write_all(response);
            let _ = tls.flush();
            tls.conn.send_close_notify();
            let _ = tls.flush();
            request
        });
        (addr, cert_pem, server)
    }

    /// bd-3894s slice (5): a `use_tls` round trip performs a REAL TLS handshake
    /// against a real rustls server (self-signed anchor installed via
    /// `with_extra_tls_roots_pem`), the framed request crosses the encrypted
    /// channel, and the peer's response comes back on the same session.
    #[test]
    fn sandboxed_tls_network_request_round_trips_bd_3894s() {
        let scratch = ScratchDir::new();
        let (addr, cert_pem, server) =
            spawn_tls_http_server(b"HTTP/1.1 200 OK\r\nContent-Length: 4\r\n\r\nbody");
        let provider = SandboxedHostIo::with_root(&scratch.path)
            .expect("provider")
            .with_extra_tls_roots_pem(cert_pem.as_bytes())
            .expect("install test trust anchor");
        let out = provider
            .perform(
                &HostIoRequest::NetworkRequest {
                    endpoint: addr.to_string(),
                    payload: b"GET /x HTTP/1.1\r\nHost: h\r\nConnection: close\r\n\r\n".to_vec(),
                    max_len: 4096,
                    use_tls: true,
                },
                &[HostIoCapability::NetworkSend],
            )
            .expect("TLS network request");
        assert_eq!(
            out,
            HostIoResponse::NetworkRequest {
                response: b"HTTP/1.1 200 OK\r\nContent-Length: 4\r\n\r\nbody".to_vec()
            },
            "the TLS round trip returns the peer's full response"
        );
        let request = server.join().expect("server thread");
        assert_eq!(
            request, b"GET /x HTTP/1.1\r\nHost: h\r\nConnection: close\r\n\r\n",
            "the decrypted request really reached the TLS server"
        );
    }

    /// bd-3894s slice (5): without the server's anchor in the trust roots the
    /// handshake MUST fail closed — no response, and critically no silent
    /// plaintext fallback.
    #[test]
    fn sandboxed_tls_untrusted_anchor_fails_closed_bd_3894s() {
        let scratch = ScratchDir::new();
        let (addr, _cert_pem, server) =
            spawn_tls_http_server(b"HTTP/1.1 200 OK\r\nContent-Length: 4\r\n\r\nbody");
        // Deliberately NOT installing the server's self-signed anchor.
        let provider = SandboxedHostIo::with_root(&scratch.path).expect("provider");
        let out = provider.perform(
            &HostIoRequest::NetworkRequest {
                endpoint: addr.to_string(),
                payload: b"GET /x HTTP/1.1\r\nHost: h\r\nConnection: close\r\n\r\n".to_vec(),
                max_len: 4096,
                use_tls: true,
            },
            &[HostIoCapability::NetworkSend],
        );
        assert!(
            matches!(out, Err(HostIoError::Io { .. })),
            "untrusted TLS anchor must fail closed, got {out:?}"
        );
        let request = server.join().expect("server thread");
        assert!(
            request.is_empty(),
            "no request bytes may reach the peer when certificate verification fails"
        );
    }

    /// bd-3894s slice (5): a `use_tls` request against a plaintext peer fails
    /// closed at the handshake (the peer answers the ClientHello with garbage) —
    /// it never degrades to sending the request in the clear.
    #[test]
    fn sandboxed_tls_to_plaintext_peer_fails_closed_bd_3894s() {
        use std::net::TcpListener;
        let scratch = ScratchDir::new();
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind listener");
        let addr = listener.local_addr().expect("local addr");
        let server = std::thread::spawn(move || {
            let (mut sock, _) = listener.accept().expect("accept");
            // A plaintext HTTP server: reply immediately without a handshake.
            let _ = sock.write_all(b"HTTP/1.1 400 Bad Request\r\n\r\n");
        });
        let provider = SandboxedHostIo::with_root(&scratch.path).expect("provider");
        let out = provider.perform(
            &HostIoRequest::NetworkRequest {
                endpoint: addr.to_string(),
                payload: b"GET / HTTP/1.1\r\nHost: h\r\nConnection: close\r\n\r\n".to_vec(),
                max_len: 4096,
                use_tls: true,
            },
            &[HostIoCapability::NetworkSend],
        );
        assert!(
            matches!(out, Err(HostIoError::Io { .. })),
            "TLS to a plaintext peer must fail closed, got {out:?}"
        );
        server.join().expect("server thread");
    }

    /// bd-3894s slice (5): the extra-roots seam is fail-closed — garbage PEM and
    /// certificate-free PEM are errors, never a silent no-op that would leave an
    /// operator's private CA unexpectedly untrusted.
    #[test]
    fn extra_tls_roots_pem_rejects_invalid_input_bd_3894s() {
        let scratch = ScratchDir::new();
        let provider = SandboxedHostIo::with_root(&scratch.path).expect("provider");
        let err = provider
            .clone()
            .with_extra_tls_roots_pem(b"this is not a pem bundle")
            .expect_err("garbage PEM must be rejected");
        assert_eq!(err.kind(), std::io::ErrorKind::InvalidData);
        let err = provider
            .with_extra_tls_roots_pem(b"")
            .expect_err("empty PEM must be rejected");
        assert_eq!(err.kind(), std::io::ErrorKind::InvalidData);
    }

    /// bd-3894s slice (4): `NetworkRequest` requires the `NetworkSend` capability
    /// (the egress is the gated action); without it the round trip fails closed
    /// before any socket opens.
    #[test]
    fn sandboxed_network_request_missing_capability_fails_closed() {
        let scratch = ScratchDir::new();
        let provider = SandboxedHostIo::with_root(&scratch.path).expect("provider");
        let out = provider.perform(
            &HostIoRequest::NetworkRequest {
                endpoint: "127.0.0.1:9".to_string(),
                payload: b"GET / HTTP/1.1\r\n\r\n".to_vec(),
                max_len: 4096,
                use_tls: false,
            },
            &[HostIoCapability::FsRead],
        );
        assert_eq!(
            out,
            Err(HostIoError::CapabilityMissing {
                capability: HostIoCapability::NetworkSend
            })
        );
    }

    #[test]
    fn sandboxed_network_missing_capability_fails_closed() {
        let scratch = ScratchDir::new();
        let provider = SandboxedHostIo::with_root(&scratch.path).expect("provider");
        let outcome = provider.perform(
            &HostIoRequest::NetworkSend {
                endpoint: "127.0.0.1:9".to_string(),
                payload: vec![1, 2, 3],
            },
            &[], // no capability granted
        );
        assert!(
            matches!(
                outcome,
                Err(HostIoError::CapabilityMissing {
                    capability: HostIoCapability::NetworkSend
                })
            ),
            "missing capability must fail closed before any connect, got {outcome:?}"
        );
    }

    #[test]
    fn sandboxed_network_send_oversize_fails_closed() {
        let scratch = ScratchDir::new();
        let provider = SandboxedHostIo::with_root_and_limit(&scratch.path, 8).expect("provider");
        // The byte cap is enforced BEFORE any connection is attempted, so no
        // server is needed (and none is left hanging on accept).
        let outcome = provider.perform(
            &HostIoRequest::NetworkSend {
                endpoint: "127.0.0.1:9".to_string(),
                payload: vec![0u8; 9],
            },
            &[HostIoCapability::NetworkSend],
        );
        assert!(
            matches!(outcome, Err(HostIoError::Io { .. })),
            "oversize network send must fail closed, got {outcome:?}"
        );
    }

    #[test]
    fn sandboxed_network_recv_oversize_fails_closed() {
        use std::net::TcpListener;
        let scratch = ScratchDir::new();
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind listener");
        let addr = listener.local_addr().expect("local addr");
        let server = std::thread::spawn(move || {
            let (mut sock, _) = listener.accept().expect("accept");
            // Stream more than the 8-byte cap; ignore a broken pipe if the
            // client tears the connection down first.
            let _ = sock.write_all(&[7u8; 9]);
        });
        let provider = SandboxedHostIo::with_root_and_limit(&scratch.path, 8).expect("provider");
        let outcome = provider.perform(
            &HostIoRequest::NetworkRecv {
                endpoint: addr.to_string(),
                max_len: 4096,
            },
            &[HostIoCapability::NetworkRecv],
        );
        assert!(
            matches!(outcome, Err(HostIoError::Io { .. })),
            "oversize network recv must fail closed, got {outcome:?}"
        );
        let _ = server.join();
    }

    #[test]
    fn sandboxed_network_empty_endpoint_fails_closed() {
        let scratch = ScratchDir::new();
        let provider = SandboxedHostIo::with_root(&scratch.path).expect("provider");
        let outcome = provider.perform(
            &HostIoRequest::NetworkSend {
                endpoint: String::new(),
                payload: vec![1, 2, 3],
            },
            &[HostIoCapability::NetworkSend],
        );
        assert!(
            matches!(outcome, Err(HostIoError::SandboxViolation { .. })),
            "empty endpoint must fail closed, got {outcome:?}"
        );
    }

    #[cfg(unix)]
    #[test]
    fn sandboxed_symlink_escape_on_read_is_rejected() {
        let scratch = ScratchDir::new();
        let outside = ScratchDir::new();
        std::fs::write(outside.path.join("secret.txt"), b"top secret").expect("outside file");
        let provider = SandboxedHostIo::with_root(&scratch.path).expect("provider");
        // Plant a symlink INSIDE the sandbox pointing OUTSIDE it.
        std::os::unix::fs::symlink(
            outside.path.join("secret.txt"),
            provider.root().join("link.txt"),
        )
        .expect("symlink");
        let outcome = provider.perform(
            &HostIoRequest::FsRead {
                path: "link.txt".to_string(),
            },
            &[HostIoCapability::FsRead],
        );
        assert!(
            matches!(outcome, Err(HostIoError::SandboxViolation { .. })),
            "a symlink escaping the root must not exfiltrate, got {outcome:?}"
        );
    }

    #[cfg(unix)]
    #[test]
    fn sandboxed_write_through_symlink_is_rejected() {
        let scratch = ScratchDir::new();
        let outside = ScratchDir::new();
        let provider = SandboxedHostIo::with_root(&scratch.path).expect("provider");
        // A symlink target inside the sandbox pointing at an outside file.
        std::os::unix::fs::symlink(
            outside.path.join("target.txt"),
            provider.root().join("evil.txt"),
        )
        .expect("symlink");
        let outcome = provider.perform(
            &HostIoRequest::FsWrite {
                path: "evil.txt".to_string(),
                data: b"escaped".to_vec(),
            },
            &[HostIoCapability::FsWrite],
        );
        assert!(
            matches!(outcome, Err(HostIoError::SandboxViolation { .. })),
            "writing through a symlink must fail closed, got {outcome:?}"
        );
        assert!(
            !outside.path.join("target.txt").exists(),
            "the write must not have escaped the sandbox"
        );
    }
}
