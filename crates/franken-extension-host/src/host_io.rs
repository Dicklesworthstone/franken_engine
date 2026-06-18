//! Sandboxed guest I/O surface for the extension host.
//!
//! The engine must not perform guest filesystem or network I/O directly. It
//! routes capability-checked requests to a host-side [`HostIoProvider`]. The
//! default provider denies every request, preserving fail-closed behavior until
//! a real sandboxed provider is deliberately installed.

use serde::{Deserialize, Serialize};

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
}
