//! Sandboxed guest I/O surface for the extension host.
//!
//! The engine must not perform guest filesystem or network I/O directly. It
//! routes capability-checked requests to a host-side [`HostIoProvider`]. The
//! default provider denies every request, preserving fail-closed behavior until
//! a real sandboxed provider is deliberately installed.

use serde::{Deserialize, Serialize};
use std::io::Read;
use std::path::{Component, Path, PathBuf};

/// Capability a guest must hold for the host to perform a given I/O request.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum HostIoCapability {
    FsRead,
    FsWrite,
    NetworkSend,
    NetworkRecv,
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
    FsRead { path: String },
    FsWrite { path: String, data: Vec<u8> },
    NetworkSend { endpoint: String, payload: Vec<u8> },
    NetworkRecv { endpoint: String, max_len: u64 },
}

impl HostIoRequest {
    #[must_use]
    pub const fn required_capability(&self) -> HostIoCapability {
        match self {
            Self::FsRead { .. } => HostIoCapability::FsRead,
            Self::FsWrite { .. } => HostIoCapability::FsWrite,
            Self::NetworkSend { .. } => HostIoCapability::NetworkSend,
            Self::NetworkRecv { .. } => HostIoCapability::NetworkRecv,
        }
    }

    #[must_use]
    pub const fn kind(&self) -> &'static str {
        match self {
            Self::FsRead { .. } => "fs_read",
            Self::FsWrite { .. } => "fs_write",
            Self::NetworkSend { .. } => "network_send",
            Self::NetworkRecv { .. } => "network_recv",
        }
    }
}

/// Successful result of a host I/O request.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", tag = "kind")]
pub enum HostIoResponse {
    FsRead { bytes: Vec<u8> },
    FsWrite { bytes_written: u64 },
    NetworkSend { bytes_sent: u64 },
    NetworkRecv { bytes: Vec<u8> },
}

/// Failure result of a host I/O request.
///
/// Every variant is fail-closed: a host that cannot positively authorize and
/// perform a request must return an error, never a partial or faked success.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", tag = "kind")]
pub enum HostIoError {
    Denied { reason: String },
    CapabilityMissing { capability: HostIoCapability },
    NotImplemented { what: String },
    SandboxViolation { detail: String },
    Io { detail: String },
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
/// Network effects are deliberately **not** performed here in the first tranche:
/// `NetworkSend` / `NetworkRecv` fail closed with [`HostIoError::Denied`].
/// Network egress must transit the product-layer SSRF policy rather than a
/// duplicated, weaker engine-side check.
#[derive(Debug, Clone)]
pub struct SandboxedHostIo {
    root: PathBuf,
    max_bytes: u64,
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
        Ok(Self { root, max_bytes })
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

    fn fs_read(&self, raw: &str) -> HostIoOutcome {
        let path = self.confine(raw)?;
        // Resolve symlinks and re-confirm the real target is inside the root, so
        // a symlink planted inside the sandbox cannot read outside it.
        let real = path.canonicalize().map_err(|err| HostIoError::Io {
            detail: format!("resolve {raw}: {err}"),
        })?;
        if !real.starts_with(&self.root) {
            return Err(HostIoError::SandboxViolation {
                detail: format!("symlinked path escapes the sandbox root: {raw}"),
            });
        }
        let metadata = std::fs::symlink_metadata(&real).map_err(|err| HostIoError::Io {
            detail: format!("stat {raw}: {err}"),
        })?;
        if !metadata.is_file() {
            return Err(HostIoError::SandboxViolation {
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
        let file = std::fs::File::open(&real).map_err(|err| HostIoError::Io {
            detail: format!("open {raw}: {err}"),
        })?;
        let mut bytes = Vec::new();
        file.take(self.max_bytes.saturating_add(1))
            .read_to_end(&mut bytes)
            .map_err(|err| HostIoError::Io {
                detail: format!("read {raw}: {err}"),
            })?;
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
        // Lexical confinement first (NUL / backslash / `..` / absolute rejection).
        self.confine(raw)?;
        // Build the target path one component at a time, refusing to traverse a
        // symlinked intermediate directory (which could redirect the write
        // outside root). `confine` guarantees only Normal/CurDir components.
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
                    return Err(HostIoError::SandboxViolation {
                        detail: format!("intermediate path component is not a directory: {raw}"),
                    });
                }
                Ok(_) => {}
                Err(_) => {
                    std::fs::create_dir(&current).map_err(|err| HostIoError::Io {
                        detail: format!("create parent for {raw}: {err}"),
                    })?;
                }
            }
        }
        current.push(file_name);
        // Refuse to write through an existing symlink target (it could redirect
        // outside root even though its parent chain is clean).
        let target_is_symlink = std::fs::symlink_metadata(&current)
            .map(|meta| meta.file_type().is_symlink())
            .unwrap_or(false);
        if target_is_symlink {
            return Err(HostIoError::SandboxViolation {
                detail: format!("refusing to write through a symlink: {raw}"),
            });
        }
        std::fs::write(&current, data).map_err(|err| HostIoError::Io {
            detail: format!("write {raw}: {err}"),
        })?;
        Ok(HostIoResponse::FsWrite {
            bytes_written: u64::try_from(data.len()).unwrap_or(u64::MAX),
        })
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
            HostIoRequest::NetworkSend { .. } | HostIoRequest::NetworkRecv { .. } => {
                Err(HostIoError::Denied {
                    reason: "sandboxed host I/O provider performs filesystem effects only; \
                             network egress is deferred to the SSRF-gated tranche"
                        .to_string(),
                })
            }
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
    /// In replay mode, return the recorded outcome for the next matching
    /// request. In record mode, return `None` so the live provider runs.
    fn replay(&self, request: &HostIoRequest) -> Option<HostIoOutcome>;

    /// In record mode, append a completed host I/O request and outcome.
    fn record(&self, request: &HostIoRequest, outcome: &HostIoOutcome);
}

/// In-memory transcript reference implementation.
#[derive(Debug)]
pub struct InMemoryHostIoTranscript {
    mode: HostIoReplayMode,
    entries: std::sync::Mutex<Vec<(HostIoRequest, HostIoOutcome)>>,
    cursor: std::sync::Mutex<usize>,
}

impl InMemoryHostIoTranscript {
    #[must_use]
    pub fn recording() -> Self {
        Self {
            mode: HostIoReplayMode::Record,
            entries: std::sync::Mutex::new(Vec::new()),
            cursor: std::sync::Mutex::new(0),
        }
    }

    #[must_use]
    pub fn replaying(entries: Vec<(HostIoRequest, HostIoOutcome)>) -> Self {
        Self {
            mode: HostIoReplayMode::Replay,
            entries: std::sync::Mutex::new(entries),
            cursor: std::sync::Mutex::new(0),
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
    fn replay(&self, request: &HostIoRequest) -> Option<HostIoOutcome> {
        if self.mode != HostIoReplayMode::Replay {
            return None;
        }

        let entries = self.entries.lock().expect("host I/O transcript mutex");
        let mut cursor = self.cursor.lock().expect("host I/O cursor mutex");
        let idx = *cursor;
        match entries.get(idx) {
            Some((recorded_request, outcome)) => {
                *cursor += 1;
                if recorded_request == request {
                    Some(outcome.clone())
                } else {
                    Some(Err(HostIoError::SandboxViolation {
                        detail: format!(
                            "host I/O replay divergence at index {idx}: live {} != recorded {}",
                            request.kind(),
                            recorded_request.kind()
                        ),
                    }))
                }
            }
            None => Some(Err(HostIoError::Denied {
                reason: format!("host I/O replay transcript exhausted at index {idx}"),
            })),
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

        let error = HostIoError::CapabilityMissing {
            capability: HostIoCapability::FsRead,
        };
        let json = serde_json::to_string(&error).expect("serialize error");
        assert_eq!(
            error,
            serde_json::from_str::<HostIoError>(&json).expect("deserialize error")
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
    }

    #[test]
    fn replay_divergence_and_exhaustion_fail_closed() {
        let replay = InMemoryHostIoTranscript::replaying(vec![(
            HostIoRequest::FsRead {
                path: "expected.txt".to_string(),
            },
            Ok(HostIoResponse::FsRead { bytes: vec![1] }),
        )]);
        let out = replay
            .replay(&HostIoRequest::FsWrite {
                path: "expected.txt".to_string(),
                data: vec![],
            })
            .expect("divergence outcome");
        assert!(matches!(out, Err(HostIoError::SandboxViolation { .. })));

        let exhausted = replay
            .replay(&HostIoRequest::FsRead {
                path: "anything.txt".to_string(),
            })
            .expect("exhausted outcome");
        assert!(matches!(exhausted, Err(HostIoError::Denied { .. })));
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
    fn sandboxed_network_effects_are_denied() {
        let scratch = ScratchDir::new();
        let provider = SandboxedHostIo::with_root(&scratch.path).expect("provider");
        let send = provider.perform(
            &HostIoRequest::NetworkSend {
                endpoint: "example.com:443".to_string(),
                payload: vec![1, 2, 3],
            },
            &[HostIoCapability::NetworkSend],
        );
        assert!(
            matches!(send, Err(HostIoError::Denied { .. })),
            "network send must be denied in the fs-only tranche, got {send:?}"
        );
        let recv = provider.perform(
            &HostIoRequest::NetworkRecv {
                endpoint: "example.com:443".to_string(),
                max_len: 16,
            },
            &[HostIoCapability::NetworkRecv],
        );
        assert!(
            matches!(recv, Err(HostIoError::Denied { .. })),
            "network recv must be denied in the fs-only tranche, got {recv:?}"
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
