//! Real descriptor writes: bytes, cursor, retained-file authority and replay.
#![cfg(unix)]
#![forbid(unsafe_code)]

use frankenengine_extension_host::host_io::{
    FsMetaResult, FsOperation, HostIoCapability, HostIoError, HostIoProvider, HostIoRecorder,
    HostIoRequest, HostIoResponse, InMemoryHostIoTranscript, SandboxedHostIo,
};
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};

struct Scratch(PathBuf);
impl Scratch {
    fn new() -> Self {
        static NEXT: AtomicU64 = AtomicU64::new(0);
        let root = std::env::temp_dir().join(format!(
            "fe-positioned-write-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::create_dir(&root).unwrap();
        Self(root)
    }
    fn provider(&self, cap: u64) -> SandboxedHostIo {
        SandboxedHostIo::with_root_and_limit(&self.0, cap).unwrap()
    }
    fn seed(&self, bytes: &[u8]) {
        std::fs::write(self.0.join("data"), bytes).unwrap();
    }
    fn bytes(&self) -> Vec<u8> {
        std::fs::read(self.0.join("data")).unwrap()
    }
}
impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}
fn request(fd: u64, positions: &[&str], bytes: &[u8]) -> HostIoRequest {
    HostIoRequest::FsMeta {
        operation: FsOperation::WriteFd,
        path: fd.to_string(),
        arguments: std::iter::once(format!("fd={fd}"))
            .chain(positions.iter().map(|value| value.to_string()))
            .collect(),
        data: bytes.to_vec(),
    }
}
fn written(count: u64) -> HostIoResponse {
    HostIoResponse::FsMeta {
        result: FsMetaResult::Unsigned(count),
    }
}
fn code(error: HostIoError, expected: &str) {
    assert!(matches!(error, HostIoError::Fs { code, .. } if code == expected));
}

#[test]
fn positioned_write_preserves_shared_cursor_and_exact_bytes() {
    let root = Scratch::new();
    root.seed(b"abcdefgh");
    let provider = root.provider(1024);
    let alias = provider.clone();
    let fd = provider.open_fd("data", "r+").unwrap();
    assert_eq!(provider.read_fd(fd, 2, None).unwrap(), b"ab");
    assert_eq!(alias.write_fd_at(fd, b"XY", Some(5)).unwrap(), 2);
    assert_eq!(provider.read_fd(fd, 2, None).unwrap(), b"cd");
    assert_eq!(provider.write_fd(fd, b"Q").unwrap(), 1);
    assert_eq!(root.bytes(), b"abcdQXYh");
    assert_eq!(alias.read_fd(fd, 1, None).unwrap(), b"X");
    provider.close_fd(fd).unwrap();
}

#[test]
fn typed_request_routes_position_and_legacy_requests_stay_sequential() {
    let root = Scratch::new();
    root.seed(b"abcdef");
    let provider = root.provider(1024);
    let fd = provider.open_fd("data", "r+").unwrap();
    assert_eq!(
        provider
            .perform(
                &request(fd, &["position=3"], &[0, 255]),
                &[HostIoCapability::FsWrite]
            )
            .unwrap(),
        written(2)
    );
    assert_eq!(
        provider
            .perform(&request(fd, &[], b"Q"), &[HostIoCapability::FsWrite])
            .unwrap(),
        written(1)
    );
    assert_eq!(root.bytes(), [b'Q', b'b', b'c', 0, 255, b'f']);
    assert_eq!(provider.read_fd(fd, 1, None).unwrap(), b"b");
}

#[test]
fn positioned_write_past_eof_zero_fills_without_seeking() {
    let root = Scratch::new();
    root.seed(b"ab");
    let provider = root.provider(1024);
    let fd = provider.open_fd("data", "r+").unwrap();
    assert_eq!(provider.write_fd_at(fd, &[128, 255], Some(5)).unwrap(), 2);
    assert_eq!(root.bytes(), [b'a', b'b', 0, 0, 0, 128, 255]);
    assert_eq!(provider.read_fd(fd, 1, None).unwrap(), b"a");
}

#[test]
fn replaced_path_cannot_redirect_a_held_descriptor() {
    let root = Scratch::new();
    root.seed(b"original");
    let provider = root.provider(1024);
    let fd = provider.open_fd("data", "r+").unwrap();
    std::fs::rename(root.0.join("data"), root.0.join("held")).unwrap();
    root.seed(b"replacement");
    provider.write_fd_at(fd, b"XYZ", Some(2)).unwrap();
    assert_eq!(std::fs::read(root.0.join("held")).unwrap(), b"orXYZnal");
    assert_eq!(root.bytes(), b"replacement");
}

#[test]
fn malformed_or_duplicate_positions_fail_before_any_mutation() {
    let root = Scratch::new();
    root.seed(b"abcdef");
    let provider = root.provider(1024);
    let fd = provider.open_fd("data", "r+").unwrap();
    for positions in [
        vec!["position="],
        vec!["position=-1"],
        vec!["position=1.5"],
        vec!["position=+2"],
        vec!["position= 2"],
        vec!["position=null"],
        vec!["position=18446744073709551616"],
        vec!["position=9223372036854775808"],
        vec!["position=0", "position=0"],
    ] {
        code(
            provider
                .perform(&request(fd, &positions, b"X"), &[HostIoCapability::FsWrite])
                .unwrap_err(),
            "EINVAL",
        );
        assert_eq!(root.bytes(), b"abcdef");
    }
    assert_eq!(provider.read_fd(fd, 1, None).unwrap(), b"a");
}

#[test]
fn offset_overflow_and_byte_limits_are_checked_before_writing() {
    let root = Scratch::new();
    root.seed(b"abcdef");
    let provider = root.provider(2);
    let fd = provider.open_fd("data", "r+").unwrap();
    for position in [u64::MAX, i64::MAX as u64, i64::MAX as u64 - 1] {
        code(
            provider.write_fd_at(fd, b"XY", Some(position)).unwrap_err(),
            "EINVAL",
        );
    }
    assert!(matches!(
        provider.write_fd_at(fd, b"XYZ", Some(1)),
        Err(HostIoError::Io { .. })
    ));
    assert_eq!(root.bytes(), b"abcdef");
    assert_eq!(provider.read_fd(fd, 1, None).unwrap(), b"a");
}

#[test]
fn capability_and_descriptor_checks_remain_fail_closed() {
    let root = Scratch::new();
    root.seed(b"abcdef");
    let provider = root.provider(1024);
    let readonly = provider.open_fd("data", "r").unwrap();
    code(
        provider.write_fd_at(readonly, b"X", Some(1)).unwrap_err(),
        "EBADF",
    );
    let fd = provider.open_fd("data", "r+").unwrap();
    assert_eq!(
        provider.perform(
            &request(fd, &["position=1"], b"X"),
            &[HostIoCapability::FsRead]
        ),
        Err(HostIoError::CapabilityMissing {
            capability: HostIoCapability::FsWrite
        })
    );
    provider.close_fd(fd).unwrap();
    for closed in [fd, 9999] {
        code(
            provider.write_fd_at(closed, b"X", Some(1)).unwrap_err(),
            "EBADF",
        );
    }
    assert_eq!(root.bytes(), b"abcdef");
}

#[test]
fn empty_positioned_write_neither_extends_nor_moves_cursor() {
    let root = Scratch::new();
    root.seed(b"abc");
    let provider = root.provider(1024);
    let fd = provider.open_fd("data", "r+").unwrap();
    assert_eq!(provider.write_fd_at(fd, &[], Some(100)).unwrap(), 0);
    assert_eq!(root.bytes(), b"abc");
    assert_eq!(provider.read_fd(fd, 1, None).unwrap(), b"a");
}

#[cfg(target_os = "linux")]
#[test]
fn linux_append_positioned_write_appends_without_moving_cursor() {
    let root = Scratch::new();
    root.seed(b"abc");
    let provider = root.provider(1024);
    let fd = provider.open_fd("data", "a+").unwrap();
    assert_eq!(provider.read_fd(fd, 1, None).unwrap(), b"a");
    provider.write_fd_at(fd, b"XY", Some(0)).unwrap();
    assert_eq!(root.bytes(), b"abcXY");
    assert_eq!(provider.read_fd(fd, 1, None).unwrap(), b"b");
}

#[test]
fn transcript_identity_commits_to_the_position() {
    let original = request(3, &["position=4"], b"XY");
    let wire = serde_json::to_string(&original).unwrap();
    assert_eq!(
        serde_json::from_str::<HostIoRequest>(&wire).unwrap(),
        original
    );
    let replay = InMemoryHostIoTranscript::replaying(vec![(original.clone(), Ok(written(2)))]);
    replay.begin_execution().unwrap();
    assert_eq!(replay.replay(&original), Some(Ok(written(2))));
    replay.finish_execution().unwrap();
    let replay = InMemoryHostIoTranscript::replaying(vec![(original, Ok(written(2)))]);
    replay.begin_execution().unwrap();
    assert!(matches!(
        replay.replay(&request(3, &["position=5"], b"XY")),
        Some(Err(HostIoError::SandboxViolation { .. }))
    ));
    assert!(replay.finish_execution().is_err());
}

#[test]
fn concurrent_provider_clones_keep_disjoint_positions_and_shared_cursor() {
    let root = Scratch::new();
    root.seed(&[0; 128]);
    let provider = root.provider(1024);
    let fd = provider.open_fd("data", "r+").unwrap();
    let mut workers = Vec::new();
    for index in 0..8u8 {
        let alias = provider.clone();
        workers.push(std::thread::spawn(move || {
            alias.write_fd_at(fd, &[index + 1; 16], Some(u64::from(index) * 16))
        }));
    }
    for worker in workers {
        assert_eq!(worker.join().unwrap().unwrap(), 16);
    }
    let expected: Vec<u8> = (1..=8).flat_map(|byte| [byte; 16]).collect();
    assert_eq!(root.bytes(), expected);
    assert_eq!(provider.read_fd(fd, 1, None).unwrap(), [1]);
}
