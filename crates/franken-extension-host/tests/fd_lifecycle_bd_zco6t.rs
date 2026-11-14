//! Sandboxed numeric fd lifecycle substrate for the bd-b0hm6 fs compat corpus
//! fixtures 0021–0023 (`fs.openSync` / `writeSync` / `readSync` / `fsyncSync`
//! / `closeSync`) — bd-zco6t.
//!
//! These tests exercise the provider layer with real files under a real
//! sandbox root, mirroring each fixture's exact byte-level semantics: 0021's
//! open-write-close round trip and count, 0022's positional read into a
//! 4-byte window at offset 2 of "abcdefgh" (== "cdef") WITHOUT moving the fd
//! cursor, and 0023's fsync durability. The interpreter/lowering wiring that
//! turns the fixture JS into these calls is tracked on the bead for the panes
//! owning those files.

#![forbid(unsafe_code)]
#![cfg(unix)]

use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};

use frankenengine_extension_host::host_io::{
    FsMetaResult, FsOperation, HostIoCapability, HostIoError, HostIoProvider, HostIoRecorder,
    HostIoRequest, HostIoResponse, InMemoryHostIoTranscript, SandboxedHostIo,
};

fn sandbox() -> (PathBuf, SandboxedHostIo) {
    let mut root = std::env::temp_dir();
    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system time should be after unix epoch")
        .as_nanos();
    root.push(format!("fe_zco6t_fd_{}_{}", std::process::id(), nonce));
    std::fs::create_dir_all(&root).expect("sandbox root");
    let provider = SandboxedHostIo::with_root(&root).expect("sandboxed provider");
    (root, provider)
}

/// Fixture 0021 shape: openSync('w') → writeSync returns the byte count →
/// closeSync → the exact bytes are on disk.
#[test]
fn fixture_0021_write_fd_roundtrip_bd_zco6t() {
    let (root, provider) = sandbox();
    let fd = provider.open_fd("fd.txt", "w").expect("openSync('w')");
    assert!(fd >= 3, "Node never hands out a stdio fd from openSync");
    let written = provider.write_fd(fd, b"fd write").expect("writeSync");
    assert_eq!(written, 8, "fixture 0021 prints the write count 8");
    provider.close_fd(fd).expect("closeSync");
    assert_eq!(
        std::fs::read(root.join("fd.txt")).expect("file on disk"),
        b"fd write",
        "fixture 0021 then reads back 'fd write'"
    );
}

/// Fixture 0022 shape: positional readSync(fd, buf, 0, 4, 2) over "abcdefgh"
/// yields exactly "cdef" — and, matching Node, the positional read must NOT
/// advance the fd cursor: a following sequential read starts at "ab".
#[test]
fn fixture_0022_positional_read_leaves_cursor_bd_zco6t() {
    let (root, provider) = sandbox();
    std::fs::write(root.join("r.txt"), b"abcdefgh").expect("seed file");
    let fd = provider.open_fd("r.txt", "r").expect("openSync('r')");

    let bytes = provider
        .read_fd(fd, 4, Some(2))
        .expect("positional readSync");
    assert_eq!(bytes, b"cdef", "fixture 0022 prints 4 then 'cdef'");
    assert_eq!(bytes.len(), 4, "the fixture's printed count is the length");

    let sequential = provider.read_fd(fd, 2, None).expect("sequential readSync");
    assert_eq!(
        sequential, b"ab",
        "a positional read must not move the cursor (Node pread semantics)"
    );
    provider.close_fd(fd).expect("closeSync");
}

/// Fixture 0023 shape: write through the fd, fsyncSync succeeds, and the
/// bytes are durable on disk after close.
#[test]
fn fixture_0023_fsync_durability_bd_zco6t() {
    let (root, provider) = sandbox();
    let fd = provider.open_fd("sync.txt", "w").expect("openSync('w')");
    provider.write_fd(fd, b"durable").expect("writeSync");
    provider.fsync_fd(fd).expect("fsyncSync");
    provider.close_fd(fd).expect("closeSync");
    assert_eq!(
        std::fs::read(root.join("sync.txt")).expect("file on disk"),
        b"durable",
        "fixture 0023 reads back 'durable'"
    );
}

/// Closed and unknown fds are EBADF — and a closed fd is never reissued, so a
/// stale guest fd cannot alias a later file.
#[test]
fn closed_fd_is_ebadf_and_never_reissued_bd_zco6t() {
    let (_root, provider) = sandbox();
    let first = provider.open_fd("one.txt", "w").expect("first open");
    provider.close_fd(first).expect("close");
    let write_err = provider.write_fd(first, b"x").expect_err("stale write");
    assert!(
        matches!(&write_err, HostIoError::Fs { code, .. } if code == "EBADF"),
        "stale fd writes must be EBADF: {write_err:?}"
    );
    let close_err = provider.close_fd(first).expect_err("double close");
    assert!(
        matches!(&close_err, HostIoError::Fs { code, .. } if code == "EBADF"),
        "double close must be EBADF: {close_err:?}"
    );
    let second = provider.open_fd("two.txt", "w").expect("second open");
    assert_ne!(second, first, "closed numeric fds are never reissued");
    provider.close_fd(second).expect("close second");
}

/// Mode enforcement: a read-only fd refuses writes and a write-only fd
/// refuses reads, both as EBADF (Node's observable behavior).
#[test]
fn wrong_mode_fd_access_is_ebadf_bd_zco6t() {
    let (root, provider) = sandbox();
    std::fs::write(root.join("mode.txt"), b"seed").expect("seed file");

    let read_only = provider.open_fd("mode.txt", "r").expect("openSync('r')");
    let err = provider
        .write_fd(read_only, b"nope")
        .expect_err("write on r");
    assert!(
        matches!(&err, HostIoError::Fs { code, .. } if code == "EBADF"),
        "write on a read-only fd must be EBADF: {err:?}"
    );
    provider.close_fd(read_only).expect("close");

    let write_only = provider.open_fd("mode.txt", "w").expect("openSync('w')");
    let err = provider
        .read_fd(write_only, 1, None)
        .expect_err("read on w");
    assert!(
        matches!(&err, HostIoError::Fs { code, .. } if code == "EBADF"),
        "read on a write-only fd must be EBADF: {err:?}"
    );
    provider.close_fd(write_only).expect("close");
}

/// Append-mode fds always write at the end, and unknown flag strings fail
/// closed before any filesystem effect.
#[test]
fn append_mode_and_unknown_flags_bd_zco6t() {
    let (root, provider) = sandbox();
    let first = provider.open_fd("log.txt", "a").expect("openSync('a')");
    provider.write_fd(first, b"one,").expect("first append");
    provider.close_fd(first).expect("close");
    let second = provider.open_fd("log.txt", "a").expect("reopen append");
    provider.write_fd(second, b"two").expect("second append");
    provider.close_fd(second).expect("close");
    assert_eq!(
        std::fs::read(root.join("log.txt")).expect("file on disk"),
        b"one,two",
        "append-mode opens must not truncate and must write at the end"
    );

    let err = provider
        .open_fd("log.txt", "wx+q")
        .expect_err("unknown flags");
    assert!(
        matches!(&err, HostIoError::Fs { code, .. } if code == "ERR_INVALID_ARG_VALUE"),
        "unknown open flags must fail closed: {err:?}"
    );
}

/// The fd surface goes through the same containment walk as every other
/// sandboxed operation: escapes are refused at open, before any fd exists.
#[test]
fn open_fd_stays_inside_the_sandbox_bd_zco6t() {
    let (_root, provider) = sandbox();
    let err = provider
        .open_fd("../escape.txt", "w")
        .expect_err("sandbox escape");
    assert!(
        !matches!(&err, HostIoError::Fs { code, .. } if code == "EBADF"),
        "an escape must be refused by containment, not fd bookkeeping: {err:?}"
    );
}

#[test]
fn fstat_observes_the_held_file_after_rename_replacement_and_unlink() {
    let (root, provider) = sandbox();
    std::fs::write(root.join("original.txt"), b"abcdef").expect("seed file");
    let fd = provider.open_fd("original.txt", "r+").expect("open file");
    assert_eq!(provider.read_fd(fd, 2, None).unwrap(), b"ab");
    let initial = provider.stat_fd(fd).expect("fstat before rename");
    assert_eq!(initial.size, 6);
    assert!(initial.is_file);
    assert!(!initial.is_directory);
    assert!(!initial.is_symbolic_link);

    std::fs::rename(root.join("original.txt"), root.join("renamed.txt")).unwrap();
    std::fs::write(
        root.join("original.txt"),
        b"a replacement with another size",
    )
    .unwrap();
    assert_eq!(provider.stat_fd(fd).unwrap(), initial);
    // Remove only this test's renamed fixture. The descriptor must remain
    // usable; resolving either its old or current pathname is incorrect.
    std::fs::remove_file(root.join("renamed.txt")).unwrap();
    assert_eq!(provider.stat_fd(fd).unwrap(), initial);
    assert_eq!(provider.read_fd(fd, 2, None).unwrap(), b"cd");
    provider.write_fd_at(fd, b"!", Some(6)).unwrap();
    assert_eq!(provider.stat_fd(fd).unwrap().size, 7);
    assert_eq!(provider.read_fd(fd, 2, None).unwrap(), b"ef");
    provider.close_fd(fd).unwrap();
    assert!(matches!(provider.stat_fd(fd), Err(HostIoError::Fs { code, .. }) if code == "EBADF"));
    let replacement = provider.open_fd("original.txt", "r").unwrap();
    assert_ne!(replacement, fd);
    assert!(matches!(provider.stat_fd(fd), Err(HostIoError::Fs { code, .. }) if code == "EBADF"));
    provider.close_fd(replacement).unwrap();
}

#[test]
fn fstat_supports_read_only_and_write_only_descriptors_without_changing_modes() {
    let (root, provider) = sandbox();
    std::fs::write(root.join("read.txt"), b"read only").unwrap();
    let read_only = provider.open_fd("read.txt", "r").unwrap();
    assert_eq!(provider.stat_fd(read_only).unwrap().size, 9);
    assert!(
        matches!(provider.write_fd(read_only, b"x"), Err(HostIoError::Fs { code, .. }) if code == "EBADF")
    );
    let write_only = provider.open_fd("write.txt", "w").unwrap();
    provider.write_fd(write_only, b"write only").unwrap();
    assert_eq!(provider.stat_fd(write_only).unwrap().size, 10);
    assert!(
        matches!(provider.read_fd(write_only, 1, None), Err(HostIoError::Fs { code, .. }) if code == "EBADF")
    );
    provider.close_fd(read_only).unwrap();
    provider.close_fd(write_only).unwrap();
}

#[test]
fn fstat_requires_read_authority_and_replays_exact_descriptor_metadata() {
    let (_root, provider) = sandbox();
    let fd = provider.open_fd("recorded.txt", "w").unwrap();
    provider.write_fd(fd, b"recorded").unwrap();
    let request = HostIoRequest::FsMeta {
        operation: FsOperation::Fstat,
        // A descriptor request never resolves its diagnostic path field.
        path: "../must-not-be-resolved".into(),
        arguments: vec![format!("fd={fd}")],
        data: Vec::new(),
    };
    assert_eq!(FsOperation::parse_name("fstat"), Some(FsOperation::Fstat));
    assert_eq!(FsOperation::Fstat.as_str(), "fstat");
    assert_eq!(request.required_capability(), HostIoCapability::FsRead);
    assert_eq!(
        provider.perform(&request, &[HostIoCapability::FsWrite]),
        Err(HostIoError::CapabilityMissing {
            capability: HostIoCapability::FsRead
        })
    );
    let outcome = provider.perform(&request, &[HostIoCapability::FsRead]);
    assert!(
        matches!(&outcome, Ok(HostIoResponse::FsMeta { result: FsMetaResult::Metadata(metadata) }) if metadata.size == 8)
    );
    let recorder = InMemoryHostIoTranscript::recording();
    recorder.begin_execution().unwrap();
    recorder.record(&request, &outcome);
    let entries = recorder.finish_execution().unwrap();
    // Round-trip the same typed request/outcome used by the effect ledger;
    // replay must work after the live descriptor is closed.
    let encoded = serde_json::to_string(&entries).unwrap();
    assert!(encoded.contains("fstat"));
    let decoded = serde_json::from_str(&encoded).unwrap();
    let replay = InMemoryHostIoTranscript::replaying(decoded);
    provider.close_fd(fd).unwrap();
    replay.begin_execution().unwrap();
    assert_eq!(replay.replay(&request), Some(outcome));
    assert_eq!(replay.finish_execution().unwrap(), entries);
}

#[test]
fn fstat_rejects_missing_malformed_unknown_and_closed_descriptors() {
    let (_root, provider) = sandbox();
    for argument in [
        None,
        Some("fd=-1"),
        Some("fd=1.5"),
        Some("fd=not-a-number"),
        Some("fd=0"),
        Some("fd=18446744073709551615"),
    ] {
        let request = HostIoRequest::FsMeta {
            operation: FsOperation::Fstat,
            path: "ignored.txt".into(),
            arguments: argument.into_iter().map(str::to_string).collect(),
            data: Vec::new(),
        };
        assert!(
            matches!(provider.perform(&request, &[HostIoCapability::FsRead]), Err(HostIoError::Fs { code, .. }) if code == "EBADF")
        );
    }
    let fd = provider.open_fd("closed.txt", "w").unwrap();
    provider.close_fd(fd).unwrap();
    assert!(matches!(provider.stat_fd(fd), Err(HostIoError::Fs { code, .. }) if code == "EBADF"));
}

fn descriptor_mutation_request(
    operation: FsOperation,
    descriptor: Option<&str>,
    arguments: &[&str],
) -> HostIoRequest {
    let mut values: Vec<String> = descriptor
        .into_iter()
        .map(|value| format!("fd={value}"))
        .collect();
    values.extend(arguments.iter().map(|value| (*value).to_string()));
    HostIoRequest::FsMeta {
        operation,
        // Descriptor mutations must never resolve this diagnostic field.
        path: "../not-the-opened-file".to_string(),
        arguments: values,
        data: Vec::new(),
    }
}

#[test]
fn descriptor_mutations_follow_the_held_inode_and_preserve_the_cursor() {
    use std::os::unix::fs::PermissionsExt;

    let (root, provider) = sandbox();
    let original = root.join("original.txt");
    let renamed = root.join("renamed.txt");
    std::fs::write(&original, b"abcdefgh").unwrap();
    let fd = provider.open_fd("original.txt", "r+").unwrap();
    assert_eq!(provider.read_fd(fd, 2, None).unwrap(), b"ab");
    std::fs::rename(&original, &renamed).unwrap();
    std::fs::write(&original, b"replacement").unwrap();
    let replacement = std::fs::metadata(&original).unwrap();

    // A clone shares the admitted descriptor; no operation may reopen its
    // former pathname or seek the file to emulate a descriptor mutation.
    let clone = provider.clone();
    clone.truncate_fd(fd, 5).unwrap();
    clone.chmod_fd(fd, 0o640).unwrap();
    clone.utimes_fd(fd, 1_250.25, 2_500.75).unwrap();
    clone.datasync_fd(fd).unwrap();
    let metadata = std::fs::metadata(&renamed).unwrap();
    assert_eq!(metadata.len(), 5);
    assert_eq!(metadata.permissions().mode() & 0o777, 0o640);
    assert_eq!(
        metadata
            .accessed()
            .unwrap()
            .duration_since(UNIX_EPOCH)
            .unwrap(),
        std::time::Duration::from_millis(1_250_250)
    );
    assert_eq!(
        metadata
            .modified()
            .unwrap()
            .duration_since(UNIX_EPOCH)
            .unwrap(),
        std::time::Duration::from_millis(2_500_750)
    );
    assert_eq!(provider.read_fd(fd, 2, None).unwrap(), b"cd");

    // This test owns the removed fixture. An unlinked inode must remain a
    // valid mutation target until the held descriptor itself is closed.
    std::fs::remove_file(&renamed).unwrap();
    clone.truncate_fd(fd, 7).unwrap();
    clone.chmod_fd(fd, 0o600).unwrap();
    clone.utimes_fd(fd, -1.25, -0.5).unwrap();
    clone.datasync_fd(fd).unwrap();
    let held = provider.stat_fd(fd).unwrap();
    assert_eq!(held.size, 7);
    assert_eq!(held.mode & 0o777, 0o600);
    assert_eq!(held.modified_millis, -500);
    assert_eq!(provider.read_fd(fd, 3, None).unwrap(), b"e\0\0");

    let unchanged = std::fs::metadata(&original).unwrap();
    assert_eq!(unchanged.len(), replacement.len());
    assert_eq!(
        unchanged.permissions().mode(),
        replacement.permissions().mode()
    );
    assert_eq!(
        unchanged.modified().unwrap(),
        replacement.modified().unwrap()
    );
    assert_eq!(std::fs::read(&original).unwrap(), b"replacement");
    clone.close_fd(fd).unwrap();
}

#[test]
fn descriptor_metadata_mutations_accept_read_only_handles_without_upgrading_them() {
    use std::os::unix::fs::PermissionsExt;

    let (root, provider) = sandbox();
    let path = root.join("read-only.txt");
    std::fs::write(&path, b"abcdef").unwrap();
    let fd = provider.open_fd("read-only.txt", "r").unwrap();
    assert_eq!(provider.read_fd(fd, 1, None).unwrap(), b"a");
    provider.datasync_fd(fd).unwrap();
    provider.chmod_fd(fd, 0o600).unwrap();
    provider.utimes_fd(fd, 1.25, 2.5).unwrap();
    let metadata = std::fs::metadata(&path).unwrap();
    assert_eq!(metadata.permissions().mode() & 0o777, 0o600);
    assert_eq!(provider.stat_fd(fd).unwrap().modified_millis, 2_500);
    let error = provider.truncate_fd(fd, 2).expect_err("read-only truncate");
    #[cfg(target_os = "linux")]
    assert!(matches!(&error, HostIoError::Fs { code, .. } if code == "EINVAL"));
    #[cfg(not(target_os = "linux"))]
    assert!(matches!(&error, HostIoError::Fs { .. }));
    assert_eq!(std::fs::read(&path).unwrap(), b"abcdef");
    assert_eq!(provider.read_fd(fd, 2, None).unwrap(), b"bc");
    assert!(
        matches!(provider.write_fd(fd, b"x"), Err(HostIoError::Fs { code, .. }) if code == "EBADF")
    );
    provider.close_fd(fd).unwrap();

    let write_only = provider.open_fd("write-only.txt", "w").unwrap();
    provider.write_fd(write_only, b"abcdef").unwrap();
    provider.truncate_fd(write_only, 3).unwrap();
    provider.chmod_fd(write_only, 0o640).unwrap();
    provider.utimes_fd(write_only, 3.25, 4.5).unwrap();
    provider.datasync_fd(write_only).unwrap();
    assert_eq!(provider.stat_fd(write_only).unwrap().size, 3);
    assert!(
        matches!(provider.read_fd(write_only, 1, None), Err(HostIoError::Fs { code, .. }) if code == "EBADF")
    );
    provider.close_fd(write_only).unwrap();
}

#[test]
fn descriptor_mutations_require_write_authority_and_replay_exact_requests() {
    let (root, provider) = sandbox();
    let fd = provider.open_fd("recorded-mutations.txt", "w+").unwrap();
    provider.write_fd(fd, b"abcdef").unwrap();
    let descriptor = fd.to_string();
    let operations: [(FsOperation, &str, &[&str]); 4] = [
        (FsOperation::Ftruncate, "ftruncate", &["length=4"]),
        (FsOperation::Fchmod, "fchmod", &["mode=384"]),
        (
            FsOperation::Futimes,
            "futimes",
            &["atime=1.25", "mtime=2.5"],
        ),
        (FsOperation::Fdatasync, "fdatasync", &[]),
    ];
    let recorder = InMemoryHostIoTranscript::recording();
    recorder.begin_execution().unwrap();
    for (operation, name, arguments) in operations {
        assert_eq!(FsOperation::parse_name(name), Some(operation));
        assert_eq!(operation.as_str(), name);
        let request = descriptor_mutation_request(operation, Some(&descriptor), arguments);
        assert_eq!(request.required_capability(), HostIoCapability::FsWrite);
        let before = provider.stat_fd(fd).unwrap();
        for denied in [
            request.clone(),
            descriptor_mutation_request(operation, Some("0"), arguments),
        ] {
            assert_eq!(
                provider.perform(&denied, &[HostIoCapability::FsRead]),
                Err(HostIoError::CapabilityMissing {
                    capability: HostIoCapability::FsWrite
                })
            );
        }
        assert_eq!(provider.stat_fd(fd).unwrap(), before);
        let outcome = provider.perform(&request, &[HostIoCapability::FsWrite]);
        assert_eq!(
            outcome,
            Ok(HostIoResponse::FsMeta {
                result: FsMetaResult::Unit
            })
        );
        recorder.record(&request, &outcome);
    }
    let entries = recorder.finish_execution().unwrap();
    assert_eq!(entries.len(), 4);
    let encoded = serde_json::to_string(&entries).unwrap();
    let decoded = serde_json::from_str(&encoded).unwrap();
    let replay = InMemoryHostIoTranscript::replaying(decoded);
    provider.close_fd(fd).unwrap();
    let later = provider.open_fd("recorded-mutations.txt", "w+").unwrap();
    assert_ne!(later, fd);
    provider.write_fd(later, b"later work").unwrap();
    let before_replay = provider.stat_fd(later).unwrap();
    replay.begin_execution().unwrap();
    for (request, outcome) in &entries {
        assert_eq!(replay.replay(request), Some(outcome.clone()));
    }
    assert_eq!(replay.finish_execution().unwrap(), entries);
    assert_eq!(provider.stat_fd(later).unwrap(), before_replay);
    assert_eq!(
        std::fs::read(root.join("recorded-mutations.txt")).unwrap(),
        b"later work"
    );
    provider.close_fd(later).unwrap();

    // A different operation or argument cannot reuse a recorded successful
    // mutation just because it carries the same numeric descriptor.
    for changed in [
        descriptor_mutation_request(FsOperation::Ftruncate, Some(&descriptor), &["length=3"]),
        descriptor_mutation_request(FsOperation::Fdatasync, Some(&descriptor), &[]),
    ] {
        let diverged = InMemoryHostIoTranscript::replaying(entries.clone());
        diverged.begin_execution().unwrap();
        assert!(matches!(
            diverged.replay(&changed),
            Some(Err(HostIoError::SandboxViolation { .. }))
        ));
        assert!(diverged.finish_execution().is_err());
    }
}

#[test]
fn descriptor_mutations_reject_invalid_descriptors_and_never_reuse_closed_ownership() {
    let (root, provider) = sandbox();
    let operations: [(FsOperation, &[&str]); 4] = [
        (FsOperation::Ftruncate, &["length=1"]),
        (FsOperation::Fchmod, &["mode=384"]),
        (FsOperation::Futimes, &["atime=1", "mtime=2"]),
        (FsOperation::Fdatasync, &[]),
    ];
    for (operation, arguments) in operations {
        for descriptor in [
            None,
            Some("-1"),
            Some("1.5"),
            Some("unknown"),
            Some("0"),
            Some("18446744073709551615"),
        ] {
            let request = descriptor_mutation_request(operation, descriptor, arguments);
            assert!(
                matches!(provider.perform(&request, &[HostIoCapability::FsWrite]), Err(HostIoError::Fs { code, .. }) if code == "EBADF")
            );
        }
    }
    let closed = provider.open_fd("closed-mutations.txt", "w+").unwrap();
    provider.close_fd(closed).unwrap();
    let live = provider.open_fd("closed-mutations.txt", "w+").unwrap();
    assert_ne!(live, closed);
    provider.write_fd(live, b"must remain").unwrap();
    let before = provider.stat_fd(live).unwrap();
    for result in [
        provider.truncate_fd(closed, 1),
        provider.chmod_fd(closed, 0o600),
        provider.utimes_fd(closed, 1.0, 2.0),
        provider.datasync_fd(closed),
    ] {
        assert!(matches!(result, Err(HostIoError::Fs { code, .. }) if code == "EBADF"));
    }
    assert_eq!(provider.stat_fd(live).unwrap(), before);
    assert_eq!(
        std::fs::read(root.join("closed-mutations.txt")).unwrap(),
        b"must remain"
    );
    provider.close_fd(live).unwrap();
}

#[test]
fn invalid_descriptor_mutation_arguments_cannot_partially_change_the_file() {
    let (root, provider) = sandbox();
    let path = root.join("invalid-arguments.txt");
    std::fs::write(&path, b"abcdef").unwrap();
    let fd = provider.open_fd("invalid-arguments.txt", "r+").unwrap();
    let descriptor = fd.to_string();
    let invalid: [(FsOperation, &[&str]); 19] = [
        (FsOperation::Ftruncate, &[]),
        (FsOperation::Ftruncate, &["length=-1"]),
        (FsOperation::Ftruncate, &["length=1.5"]),
        (FsOperation::Ftruncate, &["length=not-a-number"]),
        (FsOperation::Ftruncate, &["length=18446744073709551616"]),
        (FsOperation::Fchmod, &[]),
        (FsOperation::Fchmod, &["mode=-1"]),
        (FsOperation::Fchmod, &["mode=1.5"]),
        (FsOperation::Fchmod, &["mode=4294967296"]),
        (FsOperation::Fchmod, &["mode=not-a-number"]),
        (FsOperation::Futimes, &[]),
        (FsOperation::Futimes, &["atime=1"]),
        (FsOperation::Futimes, &["mtime=2"]),
        (FsOperation::Futimes, &["atime=NaN", "mtime=2"]),
        (FsOperation::Futimes, &["atime=1", "mtime=NaN"]),
        (FsOperation::Futimes, &["atime=1", "mtime=inf"]),
        (FsOperation::Futimes, &["atime=-inf", "mtime=2"]),
        (FsOperation::Futimes, &["atime=1", "mtime=1e30"]),
        (FsOperation::Futimes, &["atime=not-a-number", "mtime=2"]),
    ];
    let before = provider.stat_fd(fd).unwrap();
    let accessed = std::fs::metadata(&path).unwrap().accessed().unwrap();
    for (operation, arguments) in invalid {
        let request = descriptor_mutation_request(operation, Some(&descriptor), arguments);
        let outcome = provider.perform(&request, &[HostIoCapability::FsWrite]);
        assert!(
            matches!(&outcome, Err(HostIoError::Fs { code, .. }) if code == "EINVAL"),
            "{request:?}: {outcome:?}"
        );
        assert_eq!(provider.stat_fd(fd).unwrap(), before);
        assert_eq!(
            std::fs::metadata(&path).unwrap().accessed().unwrap(),
            accessed
        );
    }
    assert_eq!(provider.read_fd(fd, 6, None).unwrap(), b"abcdef");
    provider.close_fd(fd).unwrap();
}

#[test]
fn descriptor_truncate_enforces_the_host_byte_cap_before_changing_length() {
    let (root, _default_provider) = sandbox();
    std::fs::write(root.join("bounded.txt"), b"abcdef").unwrap();
    let provider = SandboxedHostIo::with_root_and_limit(&root, 8).unwrap();
    let fd = provider.open_fd("bounded.txt", "r+").unwrap();
    assert_eq!(provider.read_fd(fd, 2, None).unwrap(), b"ab");
    let before = provider.stat_fd(fd).unwrap();
    for length in [9, u64::MAX] {
        provider
            .truncate_fd(fd, length)
            .expect_err("truncate byte cap");
        assert_eq!(provider.stat_fd(fd).unwrap(), before);
        let request = descriptor_mutation_request(
            FsOperation::Ftruncate,
            Some(&fd.to_string()),
            &[&format!("length={length}")],
        );
        assert!(
            provider
                .perform(&request, &[HostIoCapability::FsWrite])
                .is_err()
        );
        assert_eq!(provider.stat_fd(fd).unwrap(), before);
    }
    provider.truncate_fd(fd, 8).unwrap();
    assert_eq!(provider.stat_fd(fd).unwrap().size, 8);
    assert_eq!(provider.read_fd(fd, 6, None).unwrap(), b"cdef\0\0");
    provider.close_fd(fd).unwrap();
    assert_eq!(
        std::fs::read(root.join("bounded.txt")).unwrap(),
        b"abcdef\0\0"
    );
}
