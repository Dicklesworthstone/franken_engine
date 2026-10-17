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
        HostIoRequest::RandomRead { byte_len: 32 },
        HostIoRequest::EnvRead {
            name: "NODE_ENV".to_string(),
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
    assert_eq!(
        HostIoRequest::RandomRead { byte_len: 32 }.required_capability(),
        HostIoCapability::RandomRead
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

    let response = HostIoResponse::RandomRead {
        bytes: vec![0, 1, 2, 255],
    };
    let json = serde_json::to_string(&response).expect("serialize random response");
    assert_eq!(
        response,
        serde_json::from_str::<HostIoResponse>(&json).expect("deserialize random response")
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
    let granted = [
        HostIoCapability::FsRead,
        HostIoCapability::NetworkRecv,
        HostIoCapability::RandomRead,
    ];
    assert!(capability_granted(&granted, HostIoCapability::FsRead));
    assert!(capability_granted(&granted, HostIoCapability::NetworkRecv));
    assert!(capability_granted(&granted, HostIoCapability::RandomRead));
    assert!(!capability_granted(&granted, HostIoCapability::FsWrite));
    assert!(!capability_granted(&[], HostIoCapability::FsRead));
}

#[test]
fn sandboxed_random_read_is_capability_checked_and_bounded() {
    let scratch = ScratchDir::new();
    let provider = SandboxedHostIo::with_root(&scratch.path).expect("provider");
    let request = HostIoRequest::RandomRead { byte_len: 32 };

    assert!(matches!(
        provider.perform(&request, &[]),
        Err(HostIoError::CapabilityMissing {
            capability: HostIoCapability::RandomRead
        })
    ));
    let outcome = provider.perform(&request, &[HostIoCapability::RandomRead]);
    assert!(
        matches!(outcome, Ok(HostIoResponse::RandomRead { ref bytes }) if bytes.len() == 32),
        "authorized random read must return exactly the requested bytes: {outcome:?}"
    );

    let oversize = HostIoRequest::RandomRead {
        byte_len: SANDBOXED_HOST_IO_MAX_RANDOM_BYTES_PER_REQUEST + 1,
    };
    assert!(matches!(
        provider.perform(&oversize, &[HostIoCapability::RandomRead]),
        Err(HostIoError::Io { .. })
    ));

    let limited = SandboxedHostIo::with_root_and_limit(&scratch.path, 4).expect("provider");
    assert!(matches!(
        limited.perform(
            &HostIoRequest::RandomRead { byte_len: 4 },
            &[HostIoCapability::RandomRead]
        ),
        Ok(HostIoResponse::RandomRead { ref bytes }) if bytes.len() == 4
    ));
    assert!(matches!(
        limited.perform(
            &HostIoRequest::RandomRead { byte_len: 5 },
            &[HostIoCapability::RandomRead]
        ),
        Err(HostIoError::Io { .. })
    ));
}

#[test]
fn sandboxed_random_budget_is_shared_across_provider_clones() {
    use std::sync::atomic::Ordering;

    let scratch = ScratchDir::new();
    let provider = SandboxedHostIo::with_root(&scratch.path).expect("provider");
    provider.random_bytes_remaining.store(4, Ordering::Release);
    let clone = provider.clone();

    let first = provider.perform(
        &HostIoRequest::RandomRead { byte_len: 3 },
        &[HostIoCapability::RandomRead],
    );
    assert!(matches!(first, Ok(HostIoResponse::RandomRead { ref bytes }) if bytes.len() == 3));
    assert!(matches!(
        clone.perform(
            &HostIoRequest::RandomRead { byte_len: 2 },
            &[HostIoCapability::RandomRead]
        ),
        Err(HostIoError::Io { .. })
    ));
    assert!(matches!(
        clone.perform(
            &HostIoRequest::RandomRead { byte_len: 1 },
            &[HostIoCapability::RandomRead]
        ),
        Ok(HostIoResponse::RandomRead { ref bytes }) if bytes.len() == 1
    ));
    assert_eq!(provider.random_bytes_remaining.load(Ordering::Acquire), 0);
    assert!(matches!(
        provider.perform(
            &HostIoRequest::RandomRead { byte_len: 1 },
            &[HostIoCapability::RandomRead]
        ),
        Err(HostIoError::Io { .. })
    ));
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
fn replaying_random_read_returns_exact_recorded_bytes_without_live_entropy() {
    let request = HostIoRequest::RandomRead { byte_len: 4 };
    let outcome = Ok(HostIoResponse::RandomRead {
        bytes: vec![0xde, 0xad, 0xbe, 0xef],
    });
    let replay = InMemoryHostIoTranscript::replaying(vec![(request.clone(), outcome.clone())]);

    replay.begin_execution().expect("begin replay");
    assert_eq!(replay.replay(&request), Some(outcome));
    assert_eq!(replay.finish_execution().expect("exact replay").len(), 1);
}

#[test]
fn replaying_random_read_rejects_length_divergence() {
    let replay = InMemoryHostIoTranscript::replaying(vec![(
        HostIoRequest::RandomRead { byte_len: 4 },
        Ok(HostIoResponse::RandomRead {
            bytes: vec![1, 2, 3, 4],
        }),
    )]);

    replay.begin_execution().expect("begin replay");
    assert!(matches!(
        replay.replay(&HostIoRequest::RandomRead { byte_len: 5 }),
        Some(Err(HostIoError::SandboxViolation { .. }))
    ));
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
fn filesystem_exception_provenance_is_explicit_and_fail_closed_bd_padqo() {
    assert_eq!(
        DenyAllHostIo.filesystem_exception_provenance(),
        HostIoExceptionProvenance::Unknown,
        "the default provider must not imply a bounded exception source"
    );

    let scratch = ScratchDir::new();
    let provider = SandboxedHostIo::with_root(&scratch.path).expect("sandboxed provider");
    assert_eq!(
        provider.filesystem_exception_provenance(),
        HostIoExceptionProvenance::ProviderInternal,
        "the canonical sandbox authenticates its bounded provider-state contract"
    );

    let recording = InMemoryHostIoTranscript::recording();
    assert_eq!(
        recording.filesystem_exception_provenance(),
        HostIoExceptionProvenance::ProviderInternal,
        "recording cannot replace a live provider outcome"
    );
    let replaying = InMemoryHostIoTranscript::replaying(Vec::new());
    assert_eq!(
        replaying.filesystem_exception_provenance(),
        HostIoExceptionProvenance::Unknown,
        "replayed outcomes remain fail-high without separate authentication"
    );
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
