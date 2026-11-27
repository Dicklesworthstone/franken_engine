//! Descriptor reads reject ambiguous requests before observing or consuming bytes.

#![forbid(unsafe_code)]
#![cfg(unix)]

use std::path::PathBuf;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use frankenengine_extension_host::host_io::{
    FsMetaResult, FsOperation, HostIoCapability, HostIoControl, HostIoError, HostIoProvider,
    HostIoRequest, HostIoResponse, SandboxedHostIo,
};

fn sandbox(max_bytes: u64) -> (PathBuf, SandboxedHostIo) {
    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system time after unix epoch")
        .as_nanos();
    let root = std::env::temp_dir().join(format!(
        "fe_positioned_reads_{}_{}",
        std::process::id(),
        nonce
    ));
    std::fs::create_dir_all(&root).expect("sandbox root");
    std::fs::write(root.join("input"), b"abcdefgh").expect("seed input");
    let provider = SandboxedHostIo::with_root_and_limit(&root, max_bytes).expect("provider");
    (root, provider)
}

fn request(fd: u64, arguments: &[&str]) -> HostIoRequest {
    let mut values = vec![format!("fd={fd}")];
    values.extend(arguments.iter().map(|argument| (*argument).to_string()));
    HostIoRequest::FsMeta {
        operation: FsOperation::ReadFd,
        // The held descriptor is authoritative; this diagnostic path is unused.
        path: "../not-the-opened-file".to_string(),
        arguments: values,
        data: Vec::new(),
    }
}

fn read(provider: &SandboxedHostIo, fd: u64, arguments: &[&str]) -> Vec<u8> {
    match provider
        .perform(&request(fd, arguments), &[HostIoCapability::FsRead])
        .expect("read request")
    {
        HostIoResponse::FsMeta {
            result: FsMetaResult::Bytes(bytes),
        } => bytes,
        response => panic!("unexpected read response: {response:?}"),
    }
}

#[test]
fn malformed_or_duplicate_positions_never_fall_back_to_sequential_reads() {
    let (root, provider) = sandbox(64);
    let cases: &[&[&str]] = &[
        &["length=2", "position="],
        &["length=2", "position=-2"],
        &["length=2", "position=-01"],
        &["length=2", "position=1.5"],
        &["length=2", "position=+2"],
        &["length=2", "position= 2"],
        &["length=2", "position=null"],
        &["length=2", "position=18446744073709551616"],
        &["length=2", "position=9223372036854775808"],
        &["length=2", "position=0", "position=0"],
        &["length=2", "position=0", "position=2"],
        &["length=2", "position=2", "position=bad"],
        &["length=2", "position=-1", "position=-1"],
        &["length=2", "position=-1", "position=2"],
        &["length=2", "position=2", "position=-1"],
    ];
    for arguments in cases {
        let fd = provider.open_fd("input", "r").unwrap();
        assert_eq!(provider.read_fd(fd, 1, None).unwrap(), b"a");
        let result = provider.perform(&request(fd, arguments), &[HostIoCapability::FsRead]);
        assert!(
            matches!(&result, Err(HostIoError::Fs { code, .. }) if code == "EINVAL"),
            "invalid position must fail closed: {arguments:?}: {result:?}"
        );
        assert_eq!(
            provider.read_fd(fd, 2, None).unwrap(),
            b"bc",
            "invalid request moved the cursor: {arguments:?}"
        );
        provider.close_fd(fd).unwrap();
    }
    assert_eq!(std::fs::read(root.join("input")).unwrap(), b"abcdefgh");
}

#[test]
fn missing_malformed_or_duplicate_lengths_are_errors_and_preserve_the_cursor() {
    let (_root, provider) = sandbox(64);
    let cases: &[&[&str]] = &[
        &[],
        &["length="],
        &["length=-1"],
        &["length=1.5"],
        &["length=+2"],
        &["length= 2"],
        &["length=null"],
        &["length=18446744073709551616"],
        &["length=0", "length=0"],
        &["length=0", "length=2"],
        &["length=2", "length=bad"],
    ];
    for arguments in cases {
        let fd = provider.open_fd("input", "r").unwrap();
        assert_eq!(provider.read_fd(fd, 1, None).unwrap(), b"a");
        let result = provider.perform(&request(fd, arguments), &[HostIoCapability::FsRead]);
        assert!(
            matches!(&result, Err(HostIoError::Fs { code, .. }) if code == "EINVAL"),
            "invalid length must not become a successful empty read: {arguments:?}: {result:?}"
        );
        assert_eq!(provider.read_fd(fd, 2, None).unwrap(), b"bc");
        provider.close_fd(fd).unwrap();
    }
}

#[test]
fn complete_positional_spans_are_validated_even_for_empty_reads() {
    let (_root, provider) = sandbox(u64::MAX);
    let fd = provider.open_fd("input", "r").unwrap();
    assert_eq!(provider.read_fd(fd, 1, None).unwrap(), b"a");
    for (position, length) in [
        (u64::MAX, 1),
        (i64::MAX as u64, 1),
        (i64::MAX as u64 - 1, 2),
        (i64::MAX as u64 + 1, 0),
        (1, u64::MAX),
    ] {
        let arguments = [format!("length={length}"), format!("position={position}")];
        let typed = provider.perform(
            &request(fd, &[&arguments[0], &arguments[1]]),
            &[HostIoCapability::FsRead],
        );
        assert!(
            matches!(&typed, Err(HostIoError::Fs { code, .. }) if code == "EINVAL"),
            "typed range {position}+{length}: {typed:?}"
        );
        let direct = provider.read_fd(fd, length, Some(position));
        assert!(
            matches!(&direct, Err(HostIoError::Fs { code, .. }) if code == "EINVAL"),
            "direct range {position}+{length}: {direct:?}"
        );
    }
    assert!(
        provider
            .read_fd(fd, 0, Some(i64::MAX as u64))
            .unwrap()
            .is_empty()
    );
    assert_eq!(provider.read_fd(fd, 2, None).unwrap(), b"bc");
    provider.close_fd(fd).unwrap();
}

#[test]
fn typed_positioned_and_sequential_reads_keep_distinct_cursor_semantics() {
    let (_root, provider) = sandbox(64);
    let fd = provider.open_fd("input", "r").unwrap();
    assert_eq!(read(&provider, fd, &["length=2"]), b"ab");
    assert_eq!(read(&provider, fd, &["length=3", "position=4"]), b"efg");
    assert!(read(&provider, fd, &["length=0", "position=1"]).is_empty());
    assert!(read(&provider, fd, &["length=0"]).is_empty());
    assert_eq!(read(&provider, fd, &["length=2", "position=-1"]), b"cd");
    assert_eq!(read(&provider, fd, &["length=8", "position=6"]), b"gh");
    assert!(read(&provider, fd, &["length=2", "position=8"]).is_empty());
    assert_eq!(read(&provider, fd, &["length=8"]), b"efgh");
    assert!(read(&provider, fd, &["length=1"]).is_empty());
    provider.close_fd(fd).unwrap();
}

#[test]
fn multi_chunk_reads_keep_every_byte_and_preserve_the_positional_cursor() {
    let (root, provider) = sandbox(128 * 1024);
    let payload: Vec<u8> = (0..32_785).map(|index| (index % 251) as u8).collect();
    std::fs::write(root.join("input"), &payload).unwrap();
    let fd = provider.open_fd("input", "r").unwrap();
    assert_eq!(read(&provider, fd, &["length=5"]), payload[..5]);
    assert_eq!(
        read(&provider, fd, &["length=20000", "position=8197"]),
        payload[8197..28_197]
    );
    assert_eq!(read(&provider, fd, &["length=32"]), payload[5..37]);
    assert_eq!(read(&provider, fd, &["length=65536"]), payload[37..]);
    assert!(read(&provider, fd, &["length=1"]).is_empty());
    provider.close_fd(fd).unwrap();
}

#[test]
fn short_eof_reads_do_not_allocate_the_entire_admitted_length() {
    let (_root, provider) = sandbox(u64::MAX);
    let fd = provider.open_fd("input", "r").unwrap();
    let length = (usize::MAX as u64).min(i64::MAX as u64);
    let arguments = [format!("length={length}"), "position=0".to_string()];
    assert_eq!(
        read(&provider, fd, &[&arguments[0], &arguments[1]]),
        b"abcdefgh"
    );
    assert_eq!(
        provider.read_fd(fd, usize::MAX as u64, None).unwrap(),
        b"abcdefgh"
    );
    assert!(
        provider
            .read_fd(fd, usize::MAX as u64, None)
            .unwrap()
            .is_empty()
    );
    provider.close_fd(fd).unwrap();
}

#[test]
fn byte_caps_authority_and_descriptor_modes_still_apply_to_read_requests() {
    let (_root, provider) = sandbox(4);
    let fd = provider.open_fd("input", "r").unwrap();
    assert_eq!(provider.read_fd(fd, 1, None).unwrap(), b"a");
    let oversized = request(fd, &["length=5"]);
    assert!(matches!(
        provider.perform(&oversized, &[HostIoCapability::FsRead]),
        Err(HostIoError::Io { .. })
    ));
    assert_eq!(
        provider.perform(&request(fd, &["length=2"]), &[HostIoCapability::FsWrite]),
        Err(HostIoError::CapabilityMissing {
            capability: HostIoCapability::FsRead,
        })
    );
    assert_eq!(provider.read_fd(fd, 2, None).unwrap(), b"bc");
    provider.close_fd(fd).unwrap();
    let write_only = provider.open_fd("write-only", "w").unwrap();
    for descriptor in [fd, write_only] {
        for arguments in [&["length=0"][..], &["length=0", "position=0"][..]] {
            assert!(
                matches!(
                    provider.perform(&request(descriptor, arguments), &[HostIoCapability::FsRead]),
                    Err(HostIoError::Fs { code, .. }) if code == "EBADF"
                ),
                "zero-byte requests must still validate fd and read authority"
            );
        }
    }
    provider.close_fd(write_only).unwrap();
}

#[derive(Debug)]
struct Cancelled;

impl HostIoControl for Cancelled {
    fn checkpoint(&self) -> Result<(), HostIoError> {
        Err(HostIoError::Denied {
            reason: "cancelled test execution".to_string(),
        })
    }
}

#[test]
fn cancelled_reads_return_no_bytes_and_leave_the_cursor_untouched() {
    let (_root, provider) = sandbox(64);
    let fd = provider.open_fd("input", "r").unwrap();
    assert_eq!(provider.read_fd(fd, 1, None).unwrap(), b"a");
    for arguments in [&["length=2"][..], &["length=2", "position=4"][..]] {
        assert!(matches!(
            provider.perform_controlled(
                &request(fd, arguments),
                &[HostIoCapability::FsRead],
                Arc::new(Cancelled),
            ),
            Err(HostIoError::Denied { .. })
        ));
    }
    assert_eq!(provider.read_fd(fd, 2, None).unwrap(), b"bc");
    provider.close_fd(fd).unwrap();
}
