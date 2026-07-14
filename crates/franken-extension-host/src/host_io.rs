//! Sandboxed guest I/O surface for the extension host.
//!
//! The engine must not perform guest filesystem or network I/O directly. It
//! routes capability-checked requests to a host-side [`HostIoProvider`]. The
//! default provider denies every request, preserving fail-closed behavior until
//! a real sandboxed provider is deliberately installed.

use serde::{Deserialize, Serialize};
use std::io::{Read, Write};
use std::net::{Shutdown, TcpStream, ToSocketAddrs};
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
/// * **Path-confined** — guest paths are interpreted relative to `root`. Empty
///   paths, NUL bytes, backslashes, absolute/rooted paths, and traversal (`..`)
///   are rejected lexically; symlink escapes are rejected by canonicalizing and
///   re-checking against the real root. A write never follows a symlinked
///   intermediate directory or target.
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
#[derive(Debug, Clone)]
pub struct SandboxedHostIo {
    root: PathBuf,
    max_bytes: u64,
    /// Trust anchors for `use_tls` round trips: the compiled-in webpki (Mozilla)
    /// roots by default, plus any operator-supplied extras added via
    /// [`Self::with_extra_tls_roots_pem`] (private CAs, test anchors). Shared via
    /// `Arc` so cloning the provider does not copy the root set.
    tls_roots: std::sync::Arc<rustls::RootCertStore>,
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
        // bd-3894s slice (5): TLS round trips verify the peer against the
        // compiled-in webpki (Mozilla) roots by default; operators extend the
        // set via `with_extra_tls_roots_pem` (private CAs, test anchors).
        let mut tls_roots = rustls::RootCertStore::empty();
        tls_roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
        Ok(Self {
            root,
            max_bytes,
            tls_roots: std::sync::Arc::new(tls_roots),
        })
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

    /// Lexically resolve a guest-supplied path to an absolute path under `root`,
    /// rejecting anything that could escape the sandbox. Does not touch the
    /// filesystem; callers additionally re-check the canonicalized real path to
    /// defeat symlink escapes.
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
        let candidate = Path::new(raw);
        for component in candidate.components() {
            match component {
                Component::Normal(_) | Component::CurDir => {}
                Component::ParentDir => {
                    return Err(HostIoError::SandboxViolation {
                        detail: format!("path traversal ('..') is not permitted: {raw}"),
                    });
                }
                Component::RootDir | Component::Prefix(_) => {
                    return Err(HostIoError::SandboxViolation {
                        detail: format!("absolute / rooted paths are not permitted: {raw}"),
                    });
                }
            }
        }
        let joined = self.root.join(candidate);
        // Lexical defense in depth (the component scan already rejects `..`).
        if !joined.starts_with(&self.root) {
            return Err(HostIoError::SandboxViolation {
                detail: format!("resolved path escapes the sandbox root: {raw}"),
            });
        }
        Ok(joined)
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

    /// Resolve an existing guest path and prove it remains inside the sandbox.
    /// `follow_final=false` canonicalizes only the parent so `lstat`/`readlink`
    /// can inspect a symlink without following its final component.
    fn existing_path(&self, raw: &str, follow_final: bool) -> Result<PathBuf, HostIoError> {
        let path = self.confine(raw)?;
        if follow_final {
            let real = path
                .canonicalize()
                .map_err(|err| Self::fs_error("resolve", raw, err))?;
            if !real.starts_with(&self.root) {
                return Err(HostIoError::SandboxViolation {
                    detail: format!("symlinked path escapes the sandbox root: {raw}"),
                });
            }
            return Ok(real);
        }

        let parent = path.parent().unwrap_or(&self.root);
        let real_parent = parent
            .canonicalize()
            .map_err(|err| Self::fs_error("resolve parent for", raw, err))?;
        if !real_parent.starts_with(&self.root) {
            return Err(HostIoError::SandboxViolation {
                detail: format!("symlinked parent escapes the sandbox root: {raw}"),
            });
        }
        let file_name = path
            .file_name()
            .ok_or_else(|| HostIoError::SandboxViolation {
                detail: format!("path resolves to no final component: {raw}"),
            })?;
        Ok(real_parent.join(file_name))
    }

    /// Resolve a mutation target while refusing symlink traversal.  When
    /// `create_parents` is true, missing parents are created one component at a
    /// time; otherwise they produce the same structured filesystem error as the
    /// underlying Node operation.
    fn prepare_write_target(
        &self,
        raw: &str,
        create_parents: bool,
    ) -> Result<PathBuf, HostIoError> {
        self.confine(raw)?;
        let normal: Vec<&std::ffi::OsStr> = Path::new(raw)
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
        let mut current = self.root.clone();
        for part in parents {
            current.push(part);
            match std::fs::symlink_metadata(&current) {
                Ok(meta) if meta.file_type().is_symlink() => {
                    return Err(HostIoError::SandboxViolation {
                        detail: format!("refusing to traverse a symlinked directory: {raw}"),
                    });
                }
                Ok(meta) if !meta.is_dir() => {
                    return Err(HostIoError::Fs {
                        code: "ENOTDIR".to_string(),
                        detail: format!("intermediate path component is not a directory: {raw}"),
                    });
                }
                Ok(_) => {}
                Err(err) if create_parents && err.kind() == std::io::ErrorKind::NotFound => {
                    std::fs::create_dir(&current)
                        .map_err(|err| Self::fs_error("create parent for", raw, err))?;
                }
                Err(err) => return Err(Self::fs_error("resolve parent for", raw, err)),
            }
        }
        current.push(file_name);
        if std::fs::symlink_metadata(&current)
            .map(|meta| meta.file_type().is_symlink())
            .unwrap_or(false)
        {
            return Err(HostIoError::SandboxViolation {
                detail: format!("refusing to mutate through a symlink: {raw}"),
            });
        }
        Ok(current)
    }

    fn fs_read(&self, raw: &str) -> HostIoOutcome {
        let real = self.existing_path(raw, true)?;
        let metadata =
            std::fs::symlink_metadata(&real).map_err(|err| Self::fs_error("stat", raw, err))?;
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
        // Bounded read: cap+1 so a file that grew between stat and read still
        // fails closed rather than being silently truncated.
        let file = std::fs::File::open(&real).map_err(|err| Self::fs_error("open", raw, err))?;
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
        let current = self.prepare_write_target(raw, false)?;
        std::fs::write(&current, data).map_err(|err| Self::fs_error("write", raw, err))?;
        Ok(HostIoResponse::FsWrite {
            bytes_written: u64::try_from(data.len()).unwrap_or(u64::MAX),
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

    fn metadata_result(raw: &str, metadata: &std::fs::Metadata) -> Result<FsMetadata, HostIoError> {
        #[cfg(unix)]
        let mode = {
            use std::os::unix::fs::MetadataExt;
            metadata.mode()
        };
        #[cfg(not(unix))]
        let mode = if metadata.permissions().readonly() {
            0o444
        } else {
            0o666
        };

        let modified = metadata
            .modified()
            .map_err(|err| Self::fs_error("read modification time for", raw, err))?;
        let modified_millis = match modified.duration_since(std::time::UNIX_EPOCH) {
            Ok(duration) => i64::try_from(duration.as_millis()).unwrap_or(i64::MAX),
            Err(err) => -i64::try_from(err.duration().as_millis()).unwrap_or(i64::MAX),
        };
        let file_type = metadata.file_type();
        Ok(FsMetadata {
            size: metadata.len(),
            mode,
            modified_millis,
            is_file: file_type.is_file(),
            is_directory: file_type.is_dir(),
            is_symbolic_link: file_type.is_symlink(),
        })
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
                let target = self.prepare_write_target(raw, false)?;
                let mut file = std::fs::OpenOptions::new()
                    .create(true)
                    .append(true)
                    .open(&target)
                    .map_err(|err| Self::fs_error("open for append", raw, err))?;
                file.write_all(data)
                    .map_err(|err| Self::fs_error("append", raw, err))?;
                FsMetaResult::Unsigned(u64::try_from(data.len()).unwrap_or(u64::MAX))
            }
            FsOperation::Exists => match self.existing_path(raw, true) {
                Ok(_) => FsMetaResult::Bool(true),
                Err(HostIoError::Fs { code, .. }) if code == "ENOENT" || code == "ENOTDIR" => {
                    FsMetaResult::Bool(false)
                }
                Err(err) => return Err(err),
            },
            FsOperation::Mkdir => {
                let recursive = Self::fs_flag(arguments, "recursive");
                let target = self.prepare_write_target(raw, recursive)?;
                let outcome = if recursive {
                    std::fs::create_dir_all(&target)
                } else {
                    std::fs::create_dir(&target)
                };
                outcome.map_err(|err| Self::fs_error("mkdir", raw, err))?;
                FsMetaResult::Unit
            }
            FsOperation::ReadDir => {
                let directory = self.existing_path(raw, true)?;
                let with_file_types = Self::fs_flag(arguments, "with_file_types");
                let mut names = Vec::new();
                let mut entries = Vec::new();
                let directory_entries = std::fs::read_dir(&directory)
                    .map_err(|err| Self::fs_error("readdir", raw, err))?;
                for entry in directory_entries {
                    let entry = entry.map_err(|err| Self::fs_error("readdir entry", raw, err))?;
                    let name = entry.file_name().to_string_lossy().into_owned();
                    if with_file_types {
                        let metadata = std::fs::symlink_metadata(entry.path())
                            .map_err(|err| Self::fs_error("stat readdir entry", raw, err))?;
                        let file_type = metadata.file_type();
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
            FsOperation::Stat | FsOperation::Lstat => {
                let follow_final = operation == FsOperation::Stat;
                let target = self.existing_path(raw, follow_final)?;
                let metadata = std::fs::symlink_metadata(&target)
                    .map_err(|err| Self::fs_error(operation.as_str(), raw, err))?;
                FsMetaResult::Metadata(Self::metadata_result(raw, &metadata)?)
            }
            FsOperation::Symlink => {
                let link_raw = arguments.first().ok_or_else(|| HostIoError::Fs {
                    code: "EINVAL".to_string(),
                    detail: "symlink requires a destination path".to_string(),
                })?;
                self.confine(raw)?;
                let link = self.prepare_write_target(link_raw, false)?;
                #[cfg(unix)]
                {
                    std::os::unix::fs::symlink(raw, &link)
                        .map_err(|err| Self::fs_error("symlink", link_raw, err))?;
                }
                #[cfg(not(unix))]
                {
                    return Err(HostIoError::NotImplemented {
                        what: "filesystem symlinks on this platform".to_string(),
                    });
                }
                FsMetaResult::Unit
            }
            FsOperation::ReadLink => {
                let target = self.existing_path(raw, false)?;
                let link = std::fs::read_link(&target)
                    .map_err(|err| Self::fs_error("readlink", raw, err))?;
                FsMetaResult::String(link.to_string_lossy().into_owned())
            }
            FsOperation::Rename | FsOperation::CopyFile => {
                let destination_raw = arguments.first().ok_or_else(|| HostIoError::Fs {
                    code: "EINVAL".to_string(),
                    detail: format!("{} requires a destination path", operation.as_str()),
                })?;
                let source = self.existing_path(raw, operation == FsOperation::CopyFile)?;
                let destination = self.prepare_write_target(destination_raw, false)?;
                if operation == FsOperation::Rename {
                    std::fs::rename(&source, &destination)
                        .map_err(|err| Self::fs_error("rename", raw, err))?;
                } else {
                    std::fs::copy(&source, &destination)
                        .map_err(|err| Self::fs_error("copy", raw, err))?;
                }
                FsMetaResult::Unit
            }
            FsOperation::Unlink => {
                let target = self.existing_path(raw, false)?;
                std::fs::remove_file(&target).map_err(|err| Self::fs_error("unlink", raw, err))?;
                FsMetaResult::Unit
            }
            FsOperation::Remove => {
                let recursive = Self::fs_flag(arguments, "recursive");
                let force = Self::fs_flag(arguments, "force");
                let target = match self.existing_path(raw, false) {
                    Ok(target) => target,
                    Err(HostIoError::Fs { code, .. }) if force && code == "ENOENT" => {
                        return Ok(HostIoResponse::FsMeta {
                            result: FsMetaResult::Unit,
                        });
                    }
                    Err(err) => return Err(err),
                };
                let metadata = match std::fs::symlink_metadata(&target) {
                    Ok(metadata) => metadata,
                    Err(err) if force && err.kind() == std::io::ErrorKind::NotFound => {
                        return Ok(HostIoResponse::FsMeta {
                            result: FsMetaResult::Unit,
                        });
                    }
                    Err(err) => return Err(Self::fs_error("stat before remove", raw, err)),
                };
                let outcome = if metadata.is_dir() {
                    if recursive {
                        std::fs::remove_dir_all(&target)
                    } else {
                        std::fs::remove_dir(&target)
                    }
                } else {
                    std::fs::remove_file(&target)
                };
                outcome.map_err(|err| Self::fs_error("remove", raw, err))?;
                FsMetaResult::Unit
            }
            FsOperation::RemoveDir => {
                let target = self.existing_path(raw, false)?;
                std::fs::remove_dir(&target).map_err(|err| Self::fs_error("rmdir", raw, err))?;
                FsMetaResult::Unit
            }
            FsOperation::Truncate => {
                let length = arguments
                    .first()
                    .and_then(|value| value.parse::<u64>().ok())
                    .unwrap_or(0);
                let target = self.existing_path(raw, true)?;
                let file = std::fs::OpenOptions::new()
                    .write(true)
                    .open(&target)
                    .map_err(|err| Self::fs_error("open for truncate", raw, err))?;
                file.set_len(length)
                    .map_err(|err| Self::fs_error("truncate", raw, err))?;
                FsMetaResult::Unit
            }
            FsOperation::Access => {
                self.existing_path(raw, true)?;
                FsMetaResult::Unit
            }
            FsOperation::Chmod => {
                let mode = arguments
                    .first()
                    .and_then(|value| value.parse::<u32>().ok())
                    .ok_or_else(|| HostIoError::Fs {
                        code: "EINVAL".to_string(),
                        detail: format!("chmod requires a numeric mode: {raw}"),
                    })?;
                let target = self.existing_path(raw, true)?;
                #[cfg(unix)]
                {
                    use std::os::unix::fs::PermissionsExt;
                    std::fs::set_permissions(&target, std::fs::Permissions::from_mode(mode))
                        .map_err(|err| Self::fs_error("chmod", raw, err))?;
                }
                #[cfg(not(unix))]
                {
                    let _ = (mode, target);
                    return Err(HostIoError::NotImplemented {
                        what: "filesystem chmod on this platform".to_string(),
                    });
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
                let target = self.existing_path(raw, true)?;
                let file = std::fs::OpenOptions::new()
                    .write(true)
                    .open(&target)
                    .map_err(|err| Self::fs_error("open for utimes", raw, err))?;
                let modified = std::time::UNIX_EPOCH
                    .checked_add(std::time::Duration::from_millis(modified_millis))
                    .ok_or_else(|| HostIoError::Fs {
                        code: "EINVAL".to_string(),
                        detail: format!("utimes timestamp is out of range: {modified_millis}"),
                    })?;
                file.set_times(std::fs::FileTimes::new().set_modified(modified))
                    .map_err(|err| Self::fs_error("utimes", raw, err))?;
                FsMetaResult::Unit
            }
            FsOperation::Realpath => {
                let target = self.existing_path(raw, true)?;
                FsMetaResult::String(target.to_string_lossy().into_owned())
            }
            FsOperation::Mkdtemp => {
                self.confine(raw)?;
                let mut created = None;
                for suffix in 0_u32..1_000_000 {
                    let candidate_raw = format!("{raw}{suffix:06}");
                    let candidate = self.prepare_write_target(&candidate_raw, false)?;
                    match std::fs::create_dir(&candidate) {
                        Ok(()) => {
                            created = Some(candidate_raw);
                            break;
                        }
                        Err(err) if err.kind() == std::io::ErrorKind::AlreadyExists => {}
                        Err(err) => return Err(Self::fs_error("mkdtemp", raw, err)),
                    }
                }
                FsMetaResult::String(created.ok_or_else(|| HostIoError::Fs {
                    code: "EEXIST".to_string(),
                    detail: format!("unable to allocate a unique temporary directory for {raw}"),
                })?)
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
    fn sandboxed_traversal_and_absolute_and_degenerate_paths_are_rejected() {
        let scratch = ScratchDir::new();
        let provider = SandboxedHostIo::with_root(&scratch.path).expect("provider");
        for raw in [
            "../escape.txt",
            "a/../../escape.txt",
            "/etc/passwd",
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
