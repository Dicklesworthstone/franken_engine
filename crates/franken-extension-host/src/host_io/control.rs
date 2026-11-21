//! Live supervisor control belongs to one host operation, not the provider.
//!
//! No watcher threads, mutable global binding, serialized authority, or new
//! ambient capability is introduced. Concurrent tenants may share a provider
//! without one tenant's cancellation revoking its siblings' network scope.

use super::network_deadline::NetworkDeadline;
use super::{HostIoError, HostIoOutcome, SandboxedHostIo};
use std::io;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

const CANCELLED: &str = "HOST_IO_EXECUTION_CANCELLED";

// A large regular-file effect must return to the supervisor between bounded
// chunks. This cannot preempt one filesystem syscall already in the kernel.
pub(super) const FILE_IO_CHUNK_BYTES: usize = 8192;

/// Read-only live authority supplied by an embedding supervisor.
///
/// A checkpoint must be bounded, nonblocking and free of guest callbacks. It
/// grants no capability. The native network provider polls it beneath TLS and
/// during DNS/connect waits. Sandboxed filesystem effects also poll between
/// path components, directory entries and bounded I/O chunks. Any refusal is a
/// non-catchable host denial, never a guest filesystem error; custom diagnostic
/// text is not exposed on the wire.
pub trait HostIoControl: std::fmt::Debug + Send + Sync {
    fn checkpoint(&self) -> Result<(), HostIoError>;
}

/// Direct host callers with no enclosing execution still retain the provider's
/// independent kill switch, resource bounds, capability checks and deadline.
#[derive(Debug, Clone, Copy, Default)]
pub struct UnrestrictedHostIoControl;

impl HostIoControl for UnrestrictedHostIoControl {
    fn checkpoint(&self) -> Result<(), HostIoError> {
        Ok(())
    }
}

#[derive(Debug, Clone)]
pub(super) struct OperationControl(Arc<OperationControlState>);

#[derive(Debug)]
struct OperationControlState {
    source: Arc<dyn HostIoControl>,
    refused: AtomicBool,
}

impl OperationControl {
    pub(super) fn new(source: Arc<dyn HostIoControl>) -> Self {
        Self(Arc::new(OperationControlState {
            source,
            refused: AtomicBool::new(false),
        }))
    }

    pub(super) fn unrestricted() -> Self {
        Self::new(Arc::new(UnrestrictedHostIoControl))
    }

    pub(super) fn check_host(&self) -> Result<(), HostIoError> {
        if !self.0.refused.load(Ordering::Acquire) && self.0.source.checkpoint().is_err() {
            self.0.refused.store(true, Ordering::Release);
        }
        if self.0.refused.load(Ordering::Acquire) {
            Err(HostIoError::Denied {
                reason: CANCELLED.to_string(),
            })
        } else {
            Ok(())
        }
    }

    pub(super) fn check_io(&self) -> io::Result<()> {
        self.check_host()
            .map_err(|_| io::Error::new(io::ErrorKind::PermissionDenied, CANCELLED))
    }

    /// The caller supplies a byte-limited reader. On refusal the outer host
    /// boundary consults this same sticky latch, retaining a host denial rather
    /// than converting the private control failure into a guest filesystem error.
    #[cfg(unix)]
    pub(super) fn read_to_end(
        &self,
        reader: &mut impl io::Read,
        output: &mut Vec<u8>,
    ) -> io::Result<()> {
        let mut chunk = [0_u8; FILE_IO_CHUNK_BYTES];
        loop {
            self.check_io()?;
            let count = match reader.read(&mut chunk) {
                Ok(0) => return Ok(()),
                Ok(count) => count,
                Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
                Err(error) => return Err(error),
            };
            output
                .try_reserve(count)
                .map_err(|_| io::Error::other("filesystem read allocation failed"))?;
            output.extend_from_slice(&chunk[..count]);
        }
    }

    /// A refused operation can already have written a prefix. Stop before any
    /// subsequent write; neither roll back those bytes nor acknowledge success.
    pub(super) fn write_all(
        &self,
        writer: &mut impl io::Write,
        mut bytes: &[u8],
    ) -> io::Result<()> {
        while !bytes.is_empty() {
            self.check_io()?;
            let count = match writer.write(&bytes[..bytes.len().min(FILE_IO_CHUNK_BYTES)]) {
                Ok(0) => return Err(io::Error::from(io::ErrorKind::WriteZero)),
                Ok(count) => count,
                Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
                Err(error) => return Err(error),
            };
            bytes = &bytes[count..];
        }
        Ok(())
    }
}

impl SandboxedHostIo {
    /// Run exactly one network effect under both independent authority sources.
    /// The local latch prevents a resettable caller signal from converting an
    /// already observed denial into success. It is never stored on the provider.
    pub(super) fn run_controlled_network(
        &self,
        control: Arc<dyn HostIoControl>,
        effect: impl FnOnce(NetworkDeadline) -> HostIoOutcome,
    ) -> HostIoOutcome {
        self.network_revocation.check_host()?;
        let control = OperationControl::new(control);
        control.check_host()?;
        let outcome = self
            .network_deadline()
            .map_err(|error| HostIoError::Io {
                detail: format!("network deadline: {error}"),
            })
            .and_then(|deadline| effect(deadline.with_control(control.clone())));
        // Check every outcome, including TLS-buffered success and native faults.
        // This does not undo effects or hide Read/Write's partial-progress count.
        self.network_revocation.check_host()?;
        control.check_host()?;
        outcome
    }
}

#[cfg(test)]
mod tests {
    use super::super::{HostIoCapability, HostIoProvider, HostIoRequest};
    use super::*;

    #[derive(Debug, Default)]
    struct Signal(AtomicBool);
    impl HostIoControl for Signal {
        fn checkpoint(&self) -> Result<(), HostIoError> {
            if self.0.load(Ordering::Acquire) {
                // Even a misclassified custom-control error cannot become a
                // catchable guest exception or disclose its private diagnostic.
                Err(HostIoError::Fs {
                    code: "EIO".into(),
                    detail: "private".into(),
                })
            } else {
                Ok(())
            }
        }
    }

    #[test]
    fn observed_refusal_is_sticky_only_within_the_current_operation() {
        let signal = Arc::new(Signal::default());
        let current = OperationControl::new(signal.clone());
        let clone = current.clone();
        signal.0.store(true, Ordering::Release);
        assert!(
            matches!(current.check_host(), Err(HostIoError::Denied { reason }) if reason == CANCELLED)
        );
        signal.0.store(false, Ordering::Release);
        assert_eq!(
            clone.check_io().unwrap_err().kind(),
            io::ErrorKind::PermissionDenied
        );
        assert!(OperationControl::new(signal).check_host().is_ok());
    }

    #[derive(Debug)]
    struct Legacy;
    impl HostIoProvider for Legacy {
        fn name(&self) -> &str {
            "legacy"
        }
        fn perform(&self, _: &HostIoRequest, _: &[HostIoCapability]) -> HostIoOutcome {
            panic!("controlled networking cannot fall back to an uninterruptible provider")
        }
    }

    #[test]
    fn uncontrolled_custom_network_provider_is_refused_before_dispatch() {
        let request = HostIoRequest::NetworkRecv {
            endpoint: "127.0.0.1:80".into(),
            max_len: 1,
        };
        assert!(matches!(
            Legacy.perform_controlled(
                &request,
                &[HostIoCapability::NetworkRecv],
                Arc::new(UnrestrictedHostIoControl)
            ),
            Err(HostIoError::NotImplemented { .. })
        ));
    }
}

#[cfg(all(test, unix))]
mod filesystem_tests {
    use super::*;
    use crate::host_io::{FsOperation, HostIoCapability, HostIoProvider, HostIoRequest};
    use std::io::Seek;
    use std::path::Path;
    use std::sync::Mutex;
    use std::sync::atomic::AtomicUsize;

    struct Predicate<F>(F);

    impl<F> std::fmt::Debug for Predicate<F> {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            f.write_str("filesystem test supervisor")
        }
    }

    impl<F: Fn() -> bool + Send + Sync> HostIoControl for Predicate<F> {
        fn checkpoint(&self) -> Result<(), HostIoError> {
            if (self.0)() {
                Err(HostIoError::Fs {
                    code: "EIO".into(),
                    detail: "private supervisor diagnostic".into(),
                })
            } else {
                Ok(())
            }
        }
    }

    fn meta(
        operation: FsOperation,
        path: &str,
        arguments: &[String],
        data: &[u8],
    ) -> HostIoRequest {
        HostIoRequest::FsMeta {
            operation,
            path: path.into(),
            arguments: arguments.to_vec(),
            data: data.to_vec(),
        }
    }

    fn assert_cancelled(outcome: HostIoOutcome) {
        assert_eq!(
            outcome.err(),
            Some(HostIoError::Denied {
                reason: CANCELLED.into()
            })
        );
    }

    fn names(path: &Path) -> Vec<std::ffi::OsString> {
        let mut names = std::fs::read_dir(path)
            .unwrap()
            .map(|entry| entry.unwrap().file_name())
            .collect::<Vec<_>>();
        names.sort();
        names
    }

    #[test]
    fn filesystem_write_stops_at_observed_prefix_and_does_not_revoke_a_sibling() {
        let directory = tempfile::tempdir().unwrap();
        let provider = SandboxedHostIo::with_root(directory.path()).unwrap();
        let path = directory.path().join("output");
        let observed = Arc::new(Mutex::new(None));
        let recorded = observed.clone();
        let watched = path.clone();
        let signal = Arc::new(Predicate(move || {
            let bytes = std::fs::read(&watched).unwrap_or_default();
            let mut recorded = recorded.lock().unwrap();
            if !bytes.is_empty() && recorded.is_none() {
                *recorded = Some(bytes);
                true
            } else {
                // A resettable source cannot undo the already observed refusal.
                false
            }
        }));
        let payload = vec![b'x'; 128 * 1024];
        assert_cancelled(provider.perform_controlled(
            &HostIoRequest::FsWrite {
                path: "output".into(),
                data: payload.clone(),
            },
            &[HostIoCapability::FsWrite],
            signal,
        ));
        let written = std::fs::read(&path).unwrap();
        assert!(!written.is_empty() && written.len() < payload.len());
        assert_eq!(written, payload[..written.len()]);
        assert_eq!(
            Some(written),
            *observed.lock().unwrap(),
            "no write may follow the observed refusal"
        );
        provider
            .clone()
            .perform(
                &HostIoRequest::FsWrite {
                    path: "sibling".into(),
                    data: b"allowed".to_vec(),
                },
                &[HostIoCapability::FsWrite],
            )
            .unwrap();
        assert_eq!(
            std::fs::read(directory.path().join("sibling")).unwrap(),
            b"allowed"
        );
    }

    #[test]
    fn filesystem_copy_cancellation_during_capture_preserves_the_destination() {
        let directory = tempfile::tempdir().unwrap();
        let provider = SandboxedHostIo::with_root(directory.path()).unwrap();
        std::fs::write(directory.path().join("source"), vec![b'x'; 1024 * 1024]).unwrap();
        std::fs::write(directory.path().join("destination"), b"retain this file").unwrap();
        let checkpoints = Arc::new(AtomicUsize::new(0));
        let calls = checkpoints.clone();
        let signal = Arc::new(Predicate(move || {
            calls.fetch_add(1, Ordering::SeqCst) >= 31
        }));
        assert_cancelled(provider.perform_controlled(
            &meta(
                FsOperation::CopyFile,
                "source",
                &["destination".into()],
                &[],
            ),
            &[HostIoCapability::FsWrite],
            signal,
        ));
        assert_eq!(checkpoints.load(Ordering::SeqCst), 32);
        assert_eq!(
            std::fs::read(directory.path().join("destination")).unwrap(),
            b"retain this file"
        );
    }

    #[test]
    fn filesystem_copy_stops_writing_and_changing_permissions_after_refusal() {
        use std::os::unix::fs::PermissionsExt;
        let directory = tempfile::tempdir().unwrap();
        let provider = SandboxedHostIo::with_root(directory.path()).unwrap();
        let source = directory.path().join("source");
        let destination = directory.path().join("destination");
        let payload = vec![b'x'; 128 * 1024];
        std::fs::write(&source, &payload).unwrap();
        std::fs::set_permissions(&source, std::fs::Permissions::from_mode(0o640)).unwrap();
        std::fs::write(&destination, b"original").unwrap();
        std::fs::set_permissions(&destination, std::fs::Permissions::from_mode(0o600)).unwrap();
        let observed = Arc::new(Mutex::new(Vec::new()));
        let recorded = observed.clone();
        let watched = destination.clone();
        let signal = Arc::new(Predicate(move || {
            let bytes = std::fs::read(&watched).unwrap();
            if bytes.first() == Some(&b'x') {
                *recorded.lock().unwrap() = bytes;
                true
            } else {
                false
            }
        }));
        assert_cancelled(provider.perform_controlled(
            &meta(
                FsOperation::CopyFile,
                "source",
                &["destination".into()],
                &[],
            ),
            &[HostIoCapability::FsWrite],
            signal,
        ));
        let bytes = std::fs::read(&destination).unwrap();
        assert!(!bytes.is_empty() && bytes.len() < payload.len());
        assert_eq!(bytes, *observed.lock().unwrap());
        assert_eq!(
            std::fs::metadata(&destination)
                .unwrap()
                .permissions()
                .mode()
                & 0o777,
            0o600
        );
    }

    #[test]
    fn filesystem_reads_and_directory_enumeration_do_not_publish_after_refusal() {
        let directory = tempfile::tempdir().unwrap();
        let provider = SandboxedHostIo::with_root(directory.path()).unwrap();
        std::fs::write(directory.path().join("input"), vec![1; 1024 * 1024]).unwrap();
        for index in 0..64 {
            std::fs::write(directory.path().join(format!("entry-{index}")), b"").unwrap();
        }
        for request in [
            HostIoRequest::FsRead {
                path: "input".into(),
            },
            meta(
                FsOperation::ReadDir,
                ".",
                &["with_file_types=true".into()],
                &[],
            ),
        ] {
            let checkpoints = Arc::new(AtomicUsize::new(0));
            let calls = checkpoints.clone();
            assert_cancelled(provider.perform_controlled(
                &request,
                &[HostIoCapability::FsRead],
                Arc::new(Predicate(move || {
                    calls.fetch_add(1, Ordering::SeqCst) >= 31
                })),
            ));
            assert_eq!(checkpoints.load(Ordering::SeqCst), 32);
        }
    }

    #[test]
    fn filesystem_descriptor_reads_stop_before_consuming_another_chunk() {
        let directory = tempfile::tempdir().unwrap();
        let provider = SandboxedHostIo::with_root(directory.path()).unwrap();
        let bytes = vec![1; 128 * 1024];
        std::fs::write(directory.path().join("input"), &bytes).unwrap();
        let fd = provider.open_fd("input", "r").unwrap();
        let observer = provider
            .fd_table
            .lock()
            .unwrap()
            .entries
            .get(&fd)
            .unwrap()
            .file
            .try_clone()
            .unwrap();
        let observer = Mutex::new(observer);
        let recorded = Arc::new(std::sync::atomic::AtomicU64::new(0));
        let cursor = recorded.clone();
        assert_cancelled(provider.perform_controlled(
            &meta(
                FsOperation::ReadFd,
                "",
                &[format!("fd={fd}"), format!("length={}", bytes.len())],
                &[],
            ),
            &[HostIoCapability::FsRead],
            Arc::new(Predicate(move || {
                let position = observer.lock().unwrap().stream_position().unwrap();
                if position != 0 {
                    cursor.store(position, Ordering::SeqCst);
                    true
                } else {
                    false
                }
            })),
        ));
        let position = recorded.load(Ordering::SeqCst);
        assert!(position > 0 && position < bytes.len() as u64);
        let mut retained = provider
            .fd_table
            .lock()
            .unwrap()
            .entries
            .get(&fd)
            .unwrap()
            .file
            .try_clone()
            .unwrap();
        assert_eq!(retained.stream_position().unwrap(), position);
        provider.close_fd(fd).unwrap();
    }

    #[test]
    fn filesystem_positioned_write_stops_without_moving_the_shared_cursor() {
        let directory = tempfile::tempdir().unwrap();
        let provider = SandboxedHostIo::with_root(directory.path()).unwrap();
        let path = directory.path().join("data");
        std::fs::write(&path, vec![0; 128 * 1024]).unwrap();
        let fd = provider.open_fd("data", "r+").unwrap();
        assert_eq!(provider.read_fd(fd, 3, None).unwrap(), [0; 3]);
        let observed = Arc::new(Mutex::new(Vec::new()));
        let recorded = observed.clone();
        let watched = path.clone();
        assert_cancelled(provider.perform_controlled(
            &meta(
                FsOperation::WriteFd,
                "",
                &[format!("fd={fd}"), "position=4096".into()],
                &vec![9; 64 * 1024],
            ),
            &[HostIoCapability::FsWrite],
            Arc::new(Predicate(move || {
                let bytes = std::fs::read(&watched).unwrap();
                if bytes[4096] == 9 {
                    *recorded.lock().unwrap() = bytes;
                    true
                } else {
                    false
                }
            })),
        ));
        let bytes = std::fs::read(&path).unwrap();
        assert_eq!(bytes, *observed.lock().unwrap());
        let written = bytes.iter().filter(|&&byte| byte == 9).count();
        assert!(written > 0 && written < 64 * 1024);
        let mut retained = provider
            .fd_table
            .lock()
            .unwrap()
            .entries
            .get(&fd)
            .unwrap()
            .file
            .try_clone()
            .unwrap();
        assert_eq!(retained.stream_position().unwrap(), 3);
        provider.close_fd(fd).unwrap();
    }

    #[test]
    fn filesystem_recursive_remove_stops_after_the_first_observed_unlink() {
        let directory = tempfile::tempdir().unwrap();
        let provider = SandboxedHostIo::with_root(directory.path()).unwrap();
        let tree = directory.path().join("tree");
        std::fs::create_dir(&tree).unwrap();
        for index in 0..8 {
            std::fs::write(tree.join(index.to_string()), b"keep").unwrap();
        }
        let remaining = Arc::new(Mutex::new(Vec::new()));
        let recorded = remaining.clone();
        let watched = tree.clone();
        let request = meta(FsOperation::Remove, "tree", &["recursive=true".into()], &[]);
        assert_cancelled(provider.perform_controlled(
            &request,
            &[HostIoCapability::FsWrite],
            Arc::new(Predicate(move || {
                let children = names(&watched);
                if children.len() < 8 {
                    *recorded.lock().unwrap() = children;
                    true
                } else {
                    false
                }
            })),
        ));
        assert_eq!(names(&tree), *remaining.lock().unwrap());
        assert_eq!(names(&tree).len(), 7);
        provider
            .perform(&request, &[HostIoCapability::FsWrite])
            .unwrap();
        assert!(!tree.exists());
    }

    #[test]
    fn filesystem_recursive_mkdir_stops_without_creating_later_components() {
        let directory = tempfile::tempdir().unwrap();
        let provider = SandboxedHostIo::with_root(directory.path()).unwrap();
        let first = directory.path().join("first");
        let watched = first.clone();
        assert_cancelled(provider.perform_controlled(
            &meta(
                FsOperation::Mkdir,
                "first/second/third",
                &["recursive=true".into()],
                &[],
            ),
            &[HostIoCapability::FsWrite],
            Arc::new(Predicate(move || watched.exists())),
        ));
        assert!(first.is_dir(), "already committed directory remains");
        assert!(!first.join("second").exists());
    }

    #[test]
    fn filesystem_cancelled_open_releases_an_unpublished_descriptor() {
        let directory = tempfile::tempdir().unwrap();
        let provider = SandboxedHostIo::with_root_and_limits(directory.path(), 1024, 1).unwrap();
        let table = provider.fd_table.clone();
        assert_cancelled(provider.perform_controlled(
            &meta(FsOperation::Open, "created", &["flags=w".into()], &[]),
            &[HostIoCapability::FsWrite],
            Arc::new(Predicate(move || {
                table
                    .try_lock()
                    .is_ok_and(|table| !table.entries.is_empty())
            })),
        ));
        assert!(
            directory.path().join("created").exists(),
            "creation is not rolled back"
        );
        assert!(provider.fd_table.lock().unwrap().entries.is_empty());
        let next = provider
            .open_fd("next", "w")
            .expect("cancelled publication releases capacity");
        provider.close_fd(next).unwrap();
    }

    #[test]
    fn filesystem_descriptor_lock_wait_rechecks_authority_before_mutation() {
        use std::os::unix::fs::PermissionsExt;
        #[derive(Debug)]
        struct Gate {
            revoked: AtomicBool,
            calls: AtomicUsize,
            arrived: std::sync::mpsc::Sender<()>,
        }
        impl HostIoControl for Gate {
            fn checkpoint(&self) -> Result<(), HostIoError> {
                let revoked = self.revoked.load(Ordering::SeqCst);
                if self.calls.fetch_add(1, Ordering::SeqCst) == 1 {
                    self.arrived.send(()).unwrap();
                }
                if revoked {
                    Err(HostIoError::Denied {
                        reason: "revoked".into(),
                    })
                } else {
                    Ok(())
                }
            }
        }
        for (operation, extra) in [
            (FsOperation::Ftruncate, vec!["length=0".into()]),
            (FsOperation::Fchmod, vec!["mode=0".into()]),
            (
                FsOperation::Futimes,
                vec!["atime=1".into(), "mtime=2".into()],
            ),
            (FsOperation::Fsync, vec![]),
            (FsOperation::Fdatasync, vec![]),
            (FsOperation::Fstat, vec![]),
            (FsOperation::CloseFd, vec![]),
        ] {
            let directory = tempfile::tempdir().unwrap();
            let provider = SandboxedHostIo::with_root(directory.path()).unwrap();
            let path = directory.path().join("file");
            std::fs::write(&path, b"unchanged").unwrap();
            let before = std::fs::metadata(&path).unwrap();
            let fd = provider.open_fd("file", "r+").unwrap();
            let mut arguments = vec![format!("fd={fd}")];
            arguments.extend(extra);
            let request = meta(operation, "", &arguments, &[]);
            let (arrived, receiver) = std::sync::mpsc::channel();
            let gate = Arc::new(Gate {
                revoked: AtomicBool::new(false),
                calls: AtomicUsize::new(0),
                arrived,
            });
            let lock = provider.fd_table.lock().unwrap();
            let worker = provider.clone();
            let signal = gate.clone();
            let join = std::thread::spawn(move || {
                worker.perform_controlled(&request, &[request.required_capability()], signal)
            });
            receiver
                .recv_timeout(std::time::Duration::from_secs(5))
                .unwrap();
            gate.revoked.store(true, Ordering::SeqCst);
            drop(lock);
            assert_cancelled(join.join().unwrap());
            let after = std::fs::metadata(&path).unwrap();
            assert_eq!(std::fs::read(&path).unwrap(), b"unchanged", "{operation:?}");
            assert_eq!(
                after.permissions().mode(),
                before.permissions().mode(),
                "{operation:?}"
            );
            assert_eq!(
                after.modified().unwrap(),
                before.modified().unwrap(),
                "{operation:?}"
            );
            provider
                .stat_fd(fd)
                .expect("cancelled close must retain the admitted descriptor");
            provider.close_fd(fd).unwrap();
        }
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn filesystem_deep_remove_uses_bounded_native_stack_and_does_not_follow_links() {
        let directory = tempfile::tempdir().unwrap();
        let outside = tempfile::tempdir().unwrap();
        let provider = SandboxedHostIo::with_root(directory.path()).unwrap();
        std::fs::write(outside.path().join("retain"), b"outside sandbox").unwrap();
        let tree = directory.path().join("tree");
        std::fs::create_dir(&tree).unwrap();
        std::os::unix::fs::symlink(outside.path(), tree.join("outside-link")).unwrap();
        let mut deepest = tree.clone();
        for _ in 0..512 {
            deepest.push("d");
            std::fs::create_dir(&deepest).unwrap();
        }
        std::fs::write(deepest.join("leaf"), b"inside sandbox").unwrap();
        std::thread::Builder::new()
            .stack_size(64 * 1024)
            .spawn(move || {
                provider.perform(
                    &meta(FsOperation::Remove, "tree", &["recursive=true".into()], &[]),
                    &[HostIoCapability::FsWrite],
                )
            })
            .unwrap()
            .join()
            .unwrap()
            .unwrap();
        assert!(!tree.exists());
        assert_eq!(
            std::fs::read(outside.path().join("retain")).unwrap(),
            b"outside sandbox"
        );
    }
}
