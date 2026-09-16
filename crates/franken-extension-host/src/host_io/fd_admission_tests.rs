//! Real-filesystem checks for bounded, pre-effect guest handle admission.

use super::*;
use std::sync::{Arc, Barrier, mpsc};

fn provider(limit: usize) -> (tempfile::TempDir, SandboxedHostIo) {
    let root = tempfile::tempdir().unwrap();
    let host = SandboxedHostIo::with_root_and_limits(root.path(), 4096, limit).unwrap();
    (root, host)
}

fn assert_fs_code<T: std::fmt::Debug>(result: Result<T, HostIoError>, expected: &str) {
    assert!(
        matches!(&result, Err(HostIoError::Fs { code, .. }) if code == expected),
        "expected {expected}, got {result:?}"
    );
}

#[test]
fn capacity_refusal_precedes_creation_and_truncation_for_every_open_mode() {
    let (root, host) = provider(1);
    std::fs::write(root.path().join("existing"), b"must survive").unwrap();
    let held = host.open_fd("existing", "r").unwrap();
    for flags in ["r", "r+", "w", "w+", "a", "a+"] {
        assert_fs_code(host.open_fd("existing", flags), "EMFILE");
        assert_fs_code(host.open_fd("not-created", flags), "EMFILE");
        assert_eq!(
            std::fs::read(root.path().join("existing")).unwrap(),
            b"must survive"
        );
        assert!(!root.path().join("not-created").exists());
    }
    assert_eq!(host.read_fd(held, 12, Some(0)).unwrap(), b"must survive");
    host.close_fd(held).unwrap();
}

#[test]
fn zero_handle_quota_preserves_one_shot_io_and_defaults_are_bounded() {
    let (root, host) = provider(0);
    assert_fs_code(host.open_fd("not-created", "w"), "EMFILE");
    assert!(!root.path().join("not-created").exists());
    assert!(
        host.perform(
            &HostIoRequest::FsWrite {
                path: "one-shot".into(),
                data: b"allowed".to_vec()
            },
            &[HostIoCapability::FsWrite],
        )
        .is_ok()
    );
    assert_eq!(
        host.perform(
            &HostIoRequest::FsRead {
                path: "one-shot".into()
            },
            &[HostIoCapability::FsRead],
        ),
        Ok(HostIoResponse::FsRead {
            bytes: b"allowed".to_vec()
        })
    );
    let default_host = SandboxedHostIo::with_root(root.path()).unwrap();
    assert_eq!(
        default_host.fd_table.lock().unwrap().max_open_files,
        SANDBOXED_HOST_IO_MAX_OPEN_FILES
    );
    assert_eq!(SANDBOXED_HOST_IO_MAX_OPEN_FILES, 1024);
}

#[test]
fn clones_share_capacity_and_close_releases_capacity_without_reusing_ids() {
    let (root, host) = provider(1);
    let other = host.clone();
    let first = host.open_fd("first", "w+").unwrap();
    assert_eq!(first, 3);
    assert_fs_code(other.open_fd("second", "w"), "EMFILE");
    assert!(!root.path().join("second").exists());
    other.write_fd(first, b"shared").unwrap();
    assert_eq!(host.read_fd(first, 6, Some(0)).unwrap(), b"shared");
    other.close_fd(first).unwrap();
    let second = other.open_fd("second", "w+").unwrap();
    assert_eq!(second, first + 1);
    assert_fs_code(host.close_fd(first), "EBADF");
    assert_fs_code(host.open_fd("third", "w"), "EMFILE");
    assert!(!root.path().join("third").exists());
    host.write_fd(second, b"new").unwrap();
    assert_eq!(std::fs::read(root.path().join("second")).unwrap(), b"new");
    host.close_fd(second).unwrap();
}

#[test]
fn concurrent_clones_cannot_spend_the_last_slot_or_create_the_losing_file() {
    let (root, host) = provider(1);
    let barrier = Arc::new(Barrier::new(3));
    let workers: Vec<_> = ["left", "right"]
        .into_iter()
        .map(|name| {
            let host = host.clone();
            let barrier = Arc::clone(&barrier);
            std::thread::spawn(move || {
                barrier.wait();
                (name, host.open_fd(name, "w+"))
            })
        })
        .collect();
    barrier.wait();
    let results: Vec<_> = workers
        .into_iter()
        .map(|worker| worker.join().unwrap())
        .collect();
    assert_eq!(
        results.iter().filter(|(_, result)| result.is_ok()).count(),
        1
    );
    for (name, result) in results {
        match result {
            Ok(fd) => {
                assert!(root.path().join(name).exists());
                host.close_fd(fd).unwrap();
            }
            Err(error) => {
                assert_fs_code::<u64>(Err(error), "EMFILE");
                assert!(!root.path().join(name).exists());
            }
        }
    }
}

#[test]
fn failed_opens_do_not_consume_capacity_or_sequence_numbers() {
    let (root, host) = provider(1);
    std::fs::create_dir(root.path().join("directory")).unwrap();
    for (path, flags) in [
        ("missing", "r"),
        ("directory", "r"),
        ("../escape", "w"),
        ("invalid", "bad-flags"),
    ] {
        assert!(host.open_fd(path, flags).is_err());
        let table = host.fd_table.lock().unwrap();
        assert!(table.entries.is_empty());
        assert_eq!(table.next_fd, 3);
    }
    assert!(!root.path().join("invalid").exists());
    let fd = host.open_fd("valid", "w+").unwrap();
    assert_eq!(fd, 3);
    host.write_fd(fd, b"ok").unwrap();
    assert_eq!(host.read_fd(fd, 2, Some(0)).unwrap(), b"ok");
    host.close_fd(fd).unwrap();
}

#[test]
fn sequence_exhaustion_fails_before_mutation_and_never_overwrites_a_live_handle() {
    let (root, host) = provider(3);
    std::fs::write(root.path().join("original"), b"keep").unwrap();
    let original = host.open_fd("original", "r").unwrap();
    host.fd_table.lock().unwrap().next_fd = u64::MAX - 1;
    let last = host.open_fd("last", "w+").unwrap();
    assert_eq!(last, u64::MAX - 1);
    host.write_fd(last, b"last").unwrap();
    assert_fs_code(host.open_fd("original", "w"), "EMFILE");
    assert_fs_code(host.open_fd("never", "w"), "EMFILE");
    assert_eq!(
        std::fs::read(root.path().join("original")).unwrap(),
        b"keep"
    );
    assert!(!root.path().join("never").exists());
    assert_eq!(host.read_fd(original, 4, Some(0)).unwrap(), b"keep");
    assert_eq!(host.read_fd(last, 4, Some(0)).unwrap(), b"last");
    host.close_fd(last).unwrap();
    assert_fs_code(host.open_fd("never", "w"), "EMFILE");
    host.close_fd(original).unwrap();
}

#[test]
fn guest_capability_refusal_does_not_spend_quota_or_touch_the_path() {
    let (root, host) = provider(1);
    let request = HostIoRequest::FsMeta {
        operation: FsOperation::Open,
        path: "not-created".into(),
        arguments: vec!["w".into()],
        data: Vec::new(),
    };
    assert_eq!(
        host.perform(&request, &[HostIoCapability::FsRead]),
        Err(HostIoError::CapabilityMissing {
            capability: HostIoCapability::FsWrite
        })
    );
    assert!(!root.path().join("not-created").exists());
    let table = host.fd_table.lock().unwrap();
    assert!(table.entries.is_empty());
    assert_eq!(table.next_fd, 3);
}

#[test]
fn fifo_open_is_rejected_without_waiting_for_a_peer_or_leaking_capacity() {
    // Rescue an old blocking implementation so a regression fails rather than
    // hanging the suite forever. No peer exists until after the guarded wait.
    for flags in ["r", "r+", "w", "w+", "a", "a+"] {
        let (root, host) = provider(1);
        let fifo = root.path().join("fifo");
        rustix::fs::mkfifoat(
            rustix::fs::CWD,
            &fifo,
            rustix::fs::Mode::from_raw_mode(0o600),
        )
        .unwrap();
        let worker_host = host.clone();
        let (send, recv) = mpsc::channel();
        let worker = std::thread::spawn(move || {
            send.send(worker_host.open_fd("fifo", flags)).unwrap();
        });
        let (before_rescue, result) = match recv.recv_timeout(Duration::from_secs(1)) {
            Ok(result) => (true, result),
            Err(mpsc::RecvTimeoutError::Timeout) => {
                let _rescue = rustix::fs::open(
                    &fifo,
                    rustix::fs::OFlags::RDWR
                        | rustix::fs::OFlags::NONBLOCK
                        | rustix::fs::OFlags::CLOEXEC,
                    rustix::fs::Mode::empty(),
                )
                .unwrap();
                (
                    false,
                    recv.recv_timeout(Duration::from_secs(2))
                        .expect("rescue unblocks FIFO open"),
                )
            }
            Err(error) => panic!("FIFO worker disconnected: {error}"),
        };
        worker.join().unwrap();
        assert!(before_rescue, "opening FIFO with {flags} waited for a peer");
        assert!(
            result.is_err(),
            "non-regular FIFO unexpectedly admitted: {result:?}"
        );
        assert!(host.fd_table.lock().unwrap().entries.is_empty());
        let fd = host.open_fd("regular", "w").unwrap();
        assert_eq!(fd, 3);
        host.close_fd(fd).unwrap();
    }
}
