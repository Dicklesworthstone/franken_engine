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
    std::fs::write(root.join("original.txt"), b"a replacement with another size").unwrap();
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
    assert!(matches!(provider.write_fd(read_only, b"x"), Err(HostIoError::Fs { code, .. }) if code == "EBADF"));
    let write_only = provider.open_fd("write.txt", "w").unwrap();
    provider.write_fd(write_only, b"write only").unwrap();
    assert_eq!(provider.stat_fd(write_only).unwrap().size, 10);
    assert!(matches!(provider.read_fd(write_only, 1, None), Err(HostIoError::Fs { code, .. }) if code == "EBADF"));
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
        Err(HostIoError::CapabilityMissing { capability: HostIoCapability::FsRead })
    );
    let outcome = provider.perform(&request, &[HostIoCapability::FsRead]);
    assert!(matches!(&outcome, Ok(HostIoResponse::FsMeta { result: FsMetaResult::Metadata(metadata) }) if metadata.size == 8));
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
    for argument in [None, Some("fd=-1"), Some("fd=1.5"), Some("fd=not-a-number"), Some("fd=0"), Some("fd=18446744073709551615")] {
        let request = HostIoRequest::FsMeta {
            operation: FsOperation::Fstat,
            path: "ignored.txt".into(),
            arguments: argument.into_iter().map(str::to_string).collect(),
            data: Vec::new(),
        };
        assert!(matches!(provider.perform(&request, &[HostIoCapability::FsRead]), Err(HostIoError::Fs { code, .. }) if code == "EBADF"));
    }
    let fd = provider.open_fd("closed.txt", "w").unwrap();
    provider.close_fd(fd).unwrap();
    assert!(matches!(provider.stat_fd(fd), Err(HostIoError::Fs { code, .. }) if code == "EBADF"));
}
