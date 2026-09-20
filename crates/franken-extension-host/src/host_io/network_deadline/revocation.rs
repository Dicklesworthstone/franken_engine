//! Irreversible, clone-shared authority for live host network operations.

use std::io;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

// This bounds requested waits, not OS scheduling or a hard containment SLO.
pub(super) const REVOCATION_POLL_INTERVAL: Duration = Duration::from_millis(25);
const REVOKED: &str = "host network authority has been revoked";

/// A host-held, irreversible network kill switch shared by provider clones.
///
/// Obtain it from [`super::super::SandboxedHostIo::network_revocation`]. Revoking
/// it refuses new network effects and interrupts in-flight DNS waits, Unix
/// connection races, TCP reads/writes and TLS transport waits. It does not
/// revoke filesystem or entropy authority. There is deliberately no reset.
///
/// Revocation is cooperative: bytes already sent cannot be recalled, a native
/// operation already entered can complete, and no effect is retried or rolled
/// back. Non-Unix blocking connect calls observe revocation on return and
/// retain their existing absolute timeout. OS DNS workers cannot be killed;
/// they keep their admission slots until they exit and cannot open sockets.
#[derive(Debug, Clone, Default)]
pub struct NetworkRevocation {
    revoked: Arc<AtomicBool>,
}

impl NetworkRevocation {
    /// Permanently revoke this network scope and every clone of it.
    pub fn revoke(&self) {
        self.revoked.store(true, Ordering::Release);
    }

    #[must_use]
    pub fn is_revoked(&self) -> bool {
        self.revoked.load(Ordering::Acquire)
    }

    pub(super) fn check(&self) -> io::Result<()> {
        if self.is_revoked() {
            // Not Interrupted: std I/O and TLS may automatically retry it.
            Err(io::Error::new(io::ErrorKind::PermissionDenied, REVOKED))
        } else {
            Ok(())
        }
    }

    pub(in crate::host_io) fn check_host(&self) -> Result<(), super::super::HostIoError> {
        if self.is_revoked() {
            Err(super::super::HostIoError::Denied {
                reason: REVOKED.to_string(),
            })
        } else {
            Ok(())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::super::{DeadlineTcpStream, NetworkDeadline};
    use super::*;
    use crate::host_io::{
        HostIoCapability, HostIoError, HostIoProvider, HostIoRequest, HostIoResponse,
        SandboxedHostIo,
    };
    use std::io::{Read, Write};
    use std::net::{Shutdown, TcpListener, TcpStream};
    use std::sync::mpsc;
    use std::time::Instant;

    fn scoped_deadline(signal: &NetworkRevocation) -> NetworkDeadline {
        NetworkDeadline {
            end: Instant::now() + Duration::from_secs(10),
            revocation: Some(signal.clone()),
            control: None,
        }
    }

    fn pair(signal: &NetworkRevocation) -> (DeadlineTcpStream, TcpStream) {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let stream = TcpStream::connect(listener.local_addr().unwrap()).unwrap();
        let (peer, _) = listener.accept().unwrap();
        peer.set_read_timeout(Some(Duration::from_secs(2))).unwrap();
        (
            DeadlineTcpStream {
                stream,
                deadline: scoped_deadline(signal),
            },
            peer,
        )
    }

    #[test]
    fn revocation_is_permanent_shared_and_not_a_retryable_interrupt() {
        let signal = NetworkRevocation::default();
        let clone = signal.clone();
        let independent = NetworkRevocation::default();
        assert!(!signal.is_revoked());
        for _ in 0..3 {
            clone.revoke();
            assert!(signal.is_revoked());
            assert_eq!(
                signal.check().unwrap_err().kind(),
                io::ErrorKind::PermissionDenied
            );
            assert!(matches!(
                signal.check_host(),
                Err(HostIoError::Denied { .. })
            ));
            assert!(!independent.is_revoked());
        }
    }

    #[test]
    fn wait_slices_do_not_shorten_or_renew_the_effect_deadline() {
        let signal = NetworkRevocation::default();
        let deadline = scoped_deadline(&signal);
        let end = deadline.end;
        assert!(deadline.remaining().unwrap() > Duration::from_secs(1));
        assert!(deadline.wait_slice().unwrap() <= REVOCATION_POLL_INTERVAL);
        assert_eq!(deadline.clone().end, end);
        signal.revoke();
        assert_eq!(
            deadline.remaining().unwrap_err().kind(),
            io::ErrorKind::PermissionDenied
        );
        assert_eq!(deadline.end, end);
    }

    #[test]
    fn revoked_socket_neither_reads_buffered_bytes_nor_writes_new_bytes() {
        let signal = NetworkRevocation::default();
        let (mut stream, mut peer) = pair(&signal);
        peer.write_all(b"already buffered").unwrap();
        signal.revoke();
        let mut buffer = [0; 32];
        assert_eq!(
            stream.read(&mut buffer).unwrap_err().kind(),
            io::ErrorKind::PermissionDenied
        );
        assert_eq!(
            stream.write(b"forbidden").unwrap_err().kind(),
            io::ErrorKind::PermissionDenied
        );
        assert_eq!(
            stream.flush().unwrap_err().kind(),
            io::ErrorKind::PermissionDenied
        );
        assert_eq!(buffer, [0; 32]);
        stream.shutdown(Shutdown::Write).unwrap();
        assert_eq!(peer.read(&mut buffer).unwrap(), 0);
    }

    #[test]
    fn partial_progress_is_reported_but_revoked_completion_is_refused() {
        for count in [0, 3] {
            let signal = NetworkRevocation::default();
            let (mut stream, _peer) = pair(&signal);
            let mut attempts = 0;
            let result = stream.retry_io(|_, _| {
                attempts += 1;
                signal.revoke();
                Ok(count)
            });
            assert_eq!(result.unwrap(), count);
            assert_eq!(
                stream.check_active().unwrap_err().kind(),
                io::ErrorKind::PermissionDenied
            );
            assert_eq!(
                stream.write(b"next").unwrap_err().kind(),
                io::ErrorKind::PermissionDenied
            );
            assert_eq!(attempts, 1);
        }
    }

    #[test]
    fn transient_waits_retry_but_partial_success_is_returned_exactly_once() {
        let signal = NetworkRevocation::default();
        let (mut stream, _peer) = pair(&signal);
        let end = stream.deadline.end;
        let mut attempts = 0;
        let count = stream
            .retry_io(|_, timeout| {
                assert!(timeout <= REVOCATION_POLL_INTERVAL);
                attempts += 1;
                match attempts {
                    1 => Err(io::ErrorKind::WouldBlock.into()),
                    2 => Err(io::ErrorKind::TimedOut.into()),
                    3 => Err(io::ErrorKind::Interrupted.into()),
                    4 => Ok(3),
                    _ => panic!("partial success must not be retried"),
                }
            })
            .unwrap();
        assert_eq!(count, 3);
        assert_eq!(attempts, 4);
        assert_eq!(stream.deadline.end, end);
    }

    #[test]
    fn revocation_interrupts_a_native_read_without_waiting_for_peer_or_deadline() {
        let signal = NetworkRevocation::default();
        let (mut stream, mut peer) = pair(&signal);
        let (entered, wait_entered) = mpsc::sync_channel(1);
        let (done, wait_done) = mpsc::sync_channel(1);
        let worker = std::thread::spawn(move || {
            let mut announced = false;
            let result = stream.retry_io(|socket, timeout| {
                socket.set_read_timeout(Some(timeout))?;
                if !announced {
                    announced = true;
                    entered.send(()).unwrap();
                }
                socket.read(&mut [0; 1])
            });
            drop(stream);
            done.send(result).unwrap();
        });
        wait_entered.recv_timeout(Duration::from_secs(2)).unwrap();
        signal.revoke();
        // The peer remains open and sends nothing. The operation's ten-second
        // deadline cannot explain a completion observed through this channel.
        let result = wait_done.recv_timeout(Duration::from_secs(2)).unwrap();
        worker.join().unwrap();
        assert_eq!(result.unwrap_err().kind(), io::ErrorKind::PermissionDenied);
        assert_eq!(peer.read(&mut [0; 1]).unwrap(), 0);
    }

    #[test]
    fn provider_clones_and_timeout_builders_cannot_reacquire_revoked_authority() {
        let root = tempfile::tempdir().unwrap();
        std::fs::write(root.path().join("kept"), b"data").unwrap();
        let provider = SandboxedHostIo::with_root(root.path()).unwrap();
        let clone = provider
            .clone()
            .with_network_timeout(Duration::from_secs(1))
            .unwrap();
        let independent = SandboxedHostIo::with_root(root.path()).unwrap();
        provider.network_revocation().revoke();
        assert!(clone.network_revocation().is_revoked());
        assert!(!independent.network_revocation().is_revoked());
        assert_eq!(
            clone.perform(
                &HostIoRequest::FsRead {
                    path: "kept".into()
                },
                &[HostIoCapability::FsRead]
            ),
            Ok(HostIoResponse::FsRead {
                bytes: b"data".to_vec()
            })
        );
    }

    #[test]
    fn revoked_default_and_pinned_entrypoints_refuse_before_connecting() {
        let root = tempfile::tempdir().unwrap();
        let provider = SandboxedHostIo::with_root(root.path()).unwrap();
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        listener.set_nonblocking(true).unwrap();
        let address = listener.local_addr().unwrap();
        let endpoint = address.to_string();
        let requests = [
            HostIoRequest::NetworkSend {
                endpoint: endpoint.clone(),
                payload: b"no".to_vec(),
            },
            HostIoRequest::NetworkRecv {
                endpoint: endpoint.clone(),
                max_len: 4096,
            },
            HostIoRequest::NetworkRequest {
                endpoint: endpoint.clone(),
                payload: b"GET / HTTP/1.1\r\n\r\n".to_vec(),
                max_len: 4096,
                use_tls: false,
            },
            HostIoRequest::NetworkRequest {
                endpoint: endpoint.clone(),
                payload: b"GET / HTTP/1.1\r\n\r\n".to_vec(),
                max_len: 4096,
                use_tls: true,
            },
        ];
        provider.network_revocation().revoke();
        for request in &requests {
            let granted = [request.required_capability()];
            assert!(matches!(
                provider.perform(request, &[]),
                Err(HostIoError::CapabilityMissing { .. })
            ));
            assert!(matches!(
                provider.perform(request, &granted),
                Err(HostIoError::Denied { .. })
            ));
            assert!(matches!(
                provider.perform_pinned_network(
                    request,
                    &granted,
                    address,
                    Instant::now() + Duration::from_secs(5)
                ),
                Err(HostIoError::Denied { .. })
            ));
            assert!(matches!(
                provider.perform_pinned_network_candidates(
                    request,
                    &granted,
                    &[address, address],
                    Instant::now() + Duration::from_secs(5)
                ),
                Err(HostIoError::Denied { .. })
            ));
        }
        for endpoint in [&*endpoint, "must-not-resolve.invalid:80"] {
            assert_eq!(
                provider
                    .resolve_network_endpoint_scoped_until(
                        endpoint,
                        Instant::now() + Duration::from_secs(5)
                    )
                    .unwrap_err()
                    .kind(),
                io::ErrorKind::PermissionDenied
            );
        }
        assert_eq!(
            listener.accept().unwrap_err().kind(),
            io::ErrorKind::WouldBlock
        );
    }
}
