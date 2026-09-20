//! One absolute budget for DNS and the socket portion of a host network effect.
//!
//! A per-read timeout alone lets a slow peer retain the interpreter forever by
//! delivering occasional bytes. Keeping the deadline underneath rustls also
//! bounds handshake loops and TLS records that produce no application bytes.

use std::io::{self, Read, Write};
use std::net::{Shutdown, SocketAddr, TcpStream};
use std::time::{Duration, Instant};

mod resolver;

#[derive(Debug, Clone, Copy)]
pub(super) struct NetworkDeadline {
    end: Instant,
}

impl NetworkDeadline {
    pub(super) fn new(timeout: Duration) -> io::Result<Self> {
        if timeout.is_zero() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "network timeout must be positive",
            ));
        }
        Instant::now()
            .checked_add(timeout)
            .map(|end| Self { end })
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "network timeout overflow"))
    }

    fn remaining(&self) -> io::Result<Duration> {
        self.end
            .checked_duration_since(Instant::now())
            .filter(|remaining| !remaining.is_zero())
            .ok_or_else(|| {
                io::Error::new(io::ErrorKind::TimedOut, "network effect deadline exceeded")
            })
    }
}

/// Owns the stream and its deadline; rustls cannot bypass the shared budget by
/// retrying a read/write internally. The timeout never restarts on progress.
#[derive(Debug)]
pub(super) struct DeadlineTcpStream {
    stream: TcpStream,
    deadline: NetworkDeadline,
}

impl DeadlineTcpStream {
    /// Resolve once, then try the bounded address list in resolver order. Each
    /// remaining address gets a share of the remaining connection budget, so a
    /// blackholed first address cannot consume every later address's chance.
    pub(super) fn connect_endpoint(endpoint: &str, deadline: NetworkDeadline) -> io::Result<Self> {
        let addresses = resolver::resolve_endpoint(endpoint, deadline)?;
        if addresses.len() == 1 {
            return Self::connect(&addresses[0], deadline);
        }
        Self::connect_addresses(&addresses, deadline, TcpStream::connect_timeout)
    }

    fn connect_addresses<F>(
        addresses: &[SocketAddr],
        deadline: NetworkDeadline,
        mut dial: F,
    ) -> io::Result<Self>
    where
        F: FnMut(&SocketAddr, Duration) -> io::Result<TcpStream>,
    {
        let mut last_error = io::Error::new(io::ErrorKind::NotFound, "no connection addresses");
        for (index, address) in addresses.iter().enumerate() {
            let attempts_left = u32::try_from(addresses.len() - index).map_err(|_| {
                io::Error::new(io::ErrorKind::InvalidInput, "too many connection addresses")
            })?;
            let timeout = deadline.remaining()? / attempts_left;
            if timeout.is_zero() {
                return Err(io::Error::new(
                    io::ErrorKind::TimedOut,
                    "network effect deadline exceeded",
                ));
            }
            let result = dial(address, timeout);
            // A late connect, successful or not, cannot restart the operation's
            // clock. Failover occurs only here, before any guest request bytes.
            deadline.remaining()?;
            match result {
                Ok(stream) => return Ok(Self { stream, deadline }),
                Err(error) => last_error = error,
            }
        }
        Err(last_error)
    }

    pub(super) fn connect(address: &SocketAddr, deadline: NetworkDeadline) -> io::Result<Self> {
        let stream = TcpStream::connect_timeout(address, deadline.remaining()?)?;
        // A late success must not start a fresh budget for the request body.
        deadline.remaining()?;
        Ok(Self { stream, deadline })
    }

    pub(super) fn shutdown(&self, how: Shutdown) -> io::Result<()> {
        self.stream.shutdown(how)
    }
}

impl Read for DeadlineTcpStream {
    fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
        if buffer.is_empty() {
            return Ok(0);
        }
        self.stream
            .set_read_timeout(Some(self.deadline.remaining()?))?;
        let count = self.stream.read(buffer)?;
        self.deadline.remaining()?;
        Ok(count)
    }
}

impl Write for DeadlineTcpStream {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        if bytes.is_empty() {
            return Ok(0);
        }
        self.stream
            .set_write_timeout(Some(self.deadline.remaining()?))?;
        let count = self.stream.write(bytes)?;
        self.deadline.remaining()?;
        Ok(count)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.deadline.remaining()?;
        self.stream.flush()
    }
}

// These inherent methods are public through SandboxedHostIo, while the socket
// and resolver machinery stays private to the engine. The product supplies an
// already-authorized destination; this module does not duplicate SSRF policy.
impl super::SandboxedHostIo {
    /// The provider's upper bound for one complete network effect. The product
    /// can start this budget before DNS and carry it into pinned execution.
    #[must_use]
    pub fn network_timeout(&self) -> Duration {
        self.network_timeout
    }

    /// Resolve with the engine's process-wide admission limit and an absolute
    /// caller deadline. A timed-out OS call keeps its worker permit until it
    /// exits. No resolver worker can open a connection or perform a guest effect.
    /// The product must check the returned addresses against its egress policy.
    pub fn resolve_network_endpoint_until(
        endpoint: &str,
        deadline: Instant,
    ) -> io::Result<Vec<SocketAddr>> {
        resolver::resolve_endpoint(endpoint, NetworkDeadline { end: deadline })
    }

    /// Perform a network request at exactly the product-approved destination.
    ///
    /// The original request remains the transcript and HTTP/TLS identity. DNS is
    /// never consulted here, even for HTTPS: the socket uses `destination`, SNI
    /// and certificate verification use the original endpoint's host, and the
    /// existing root store (including operator extras) remains authoritative.
    ///
    /// Both the caller's absolute deadline and this provider's configured limit
    /// apply. There are no automatic retries, redirects, plaintext fallbacks,
    /// or relaxed certificate checks. Non-network requests and mismatched ports
    /// or literal identities fail before socket creation. This is a trusted
    /// host API: authorization of a DNS name's resolved IP belongs to the caller.
    pub fn perform_pinned_network(
        &self,
        request: &super::HostIoRequest,
        granted: &[super::HostIoCapability],
        destination: SocketAddr,
        deadline: Instant,
    ) -> super::HostIoOutcome {
        use super::{HostIoError, HostIoRequest, HostIoResponse};

        let capability = request.required_capability();
        if !granted.contains(&capability) {
            return Err(HostIoError::CapabilityMissing { capability });
        }
        let (endpoint, payload) = match request {
            HostIoRequest::NetworkSend { endpoint, payload }
            | HostIoRequest::NetworkRequest {
                endpoint, payload, ..
            } => (endpoint.as_str(), Some(payload.as_slice())),
            HostIoRequest::NetworkRecv { endpoint, .. } => (endpoint.as_str(), None),
            _ => {
                return Err(HostIoError::SandboxViolation {
                    detail: "pinned network entrypoint requires a network request".to_string(),
                });
            }
        };
        let fail = |error: io::Error| HostIoError::Io {
            detail: format!("pinned network {endpoint}: {error}"),
        };
        let identity = pinned_identity(endpoint, destination).map_err(fail)?;
        if payload
            .is_some_and(|bytes| u64::try_from(bytes.len()).unwrap_or(u64::MAX) > self.max_bytes)
        {
            return Err(HostIoError::Io {
                detail: format!(
                    "pinned network request exceeds the {}-byte cap",
                    self.max_bytes
                ),
            });
        }
        let provider_deadline = NetworkDeadline::new(self.network_timeout).map_err(fail)?;
        let deadline = NetworkDeadline {
            end: deadline.min(provider_deadline.end),
        };
        deadline.remaining().map_err(fail)?;

        if let HostIoRequest::NetworkRequest {
            payload,
            max_len,
            use_tls: true,
            ..
        } = request
        {
            let provider = std::sync::Arc::new(rustls::crypto::ring::default_provider());
            let config = rustls::ClientConfig::builder_with_provider(provider)
                .with_safe_default_protocol_versions()
                .map_err(|error| HostIoError::Io {
                    detail: format!("TLS protocol setup: {error}"),
                })?
                .with_root_certificates(rustls::RootCertStore::clone(&self.tls_roots))
                .with_no_client_auth();
            let connection = rustls::ClientConnection::new(std::sync::Arc::new(config), identity)
                .map_err(|error| HostIoError::Io {
                detail: format!("TLS client setup: {error}"),
            })?;
            // This is the sole connect operation. In particular, do not call
            // self.connect(endpoint), which would resolve the name a second time.
            let socket = DeadlineTcpStream::connect(&destination, deadline).map_err(fail)?;
            let mut tls = rustls::StreamOwned::new(connection, socket);
            tls.write_all(payload).map_err(fail)?;
            tls.flush().map_err(fail)?;
            let response = super::http_response::read_response(
                &mut tls,
                payload,
                (*max_len).min(self.max_bytes),
            )
            .map_err(fail)?;
            deadline.remaining().map_err(fail)?;
            return Ok(HostIoResponse::NetworkRequest { response });
        }

        let mut stream = DeadlineTcpStream::connect(&destination, deadline).map_err(fail)?;
        let outcome = match request {
            HostIoRequest::NetworkSend { payload, .. } => {
                stream.write_all(payload).map_err(fail)?;
                stream.flush().map_err(fail)?;
                HostIoResponse::NetworkSend {
                    bytes_sent: u64::try_from(payload.len()).unwrap_or(u64::MAX),
                }
            }
            HostIoRequest::NetworkRecv { max_len, .. } => {
                let cap = (*max_len).min(self.max_bytes);
                let mut bytes = Vec::new();
                stream
                    .take(cap.saturating_add(1))
                    .read_to_end(&mut bytes)
                    .map_err(fail)?;
                if u64::try_from(bytes.len()).unwrap_or(u64::MAX) > cap {
                    return Err(HostIoError::Io {
                        detail: format!("pinned network receive exceeds the {cap}-byte cap"),
                    });
                }
                HostIoResponse::NetworkRecv { bytes }
            }
            HostIoRequest::NetworkRequest {
                payload, max_len, ..
            } => {
                stream.write_all(payload).map_err(fail)?;
                stream.flush().map_err(fail)?;
                let _ = stream.shutdown(Shutdown::Write);
                let response = super::http_response::read_response(
                    &mut stream,
                    payload,
                    (*max_len).min(self.max_bytes),
                )
                .map_err(fail)?;
                HostIoResponse::NetworkRequest { response }
            }
            _ => unreachable!("non-network requests were rejected before connecting"),
        };
        deadline.remaining().map_err(fail)?;
        Ok(outcome)
    }
}

/// Keep routing separate from authentication, while refusing a changed port or
/// changed numeric identity. Validating the DNS name never performs a lookup.
fn pinned_identity(
    endpoint: &str,
    destination: SocketAddr,
) -> io::Result<rustls_pki_types::ServerName<'static>> {
    let invalid = || {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            "invalid pinned network authority",
        )
    };
    if endpoint.len() > 260 || !endpoint.is_ascii() || destination.port() == 0 {
        return Err(invalid());
    }
    if let Ok(original) = endpoint.parse::<SocketAddr>() {
        if original != destination {
            return Err(invalid());
        }
        return Ok(rustls_pki_types::ServerName::from(original.ip()));
    }
    let (host, port) = endpoint.rsplit_once(':').ok_or_else(invalid)?;
    if host.is_empty()
        || port.is_empty()
        || !port.bytes().all(|byte| byte.is_ascii_digit())
        || port.parse::<u16>().ok() != Some(destination.port())
    {
        return Err(invalid());
    }
    // Require an actual DNS identity here. Malformed/shortened numeric aliases
    // must not become a way to authenticate one IP while dialing another.
    if host
        .bytes()
        .all(|byte| byte.is_ascii_digit() || byte == b'.')
    {
        return Err(invalid());
    }
    match rustls_pki_types::ServerName::try_from(host.to_string()).map_err(|_| invalid())? {
        name @ rustls_pki_types::ServerName::DnsName(_) => Ok(name),
        _ => Err(invalid()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::TcpListener;

    #[test]
    fn zero_and_unrepresentable_timeouts_are_errors_not_panics() {
        for timeout in [Duration::ZERO, Duration::MAX] {
            assert_eq!(
                NetworkDeadline::new(timeout).unwrap_err().kind(),
                io::ErrorKind::InvalidInput
            );
        }
    }

    #[test]
    fn expired_deadline_cannot_be_renewed_by_another_operation() {
        let deadline = NetworkDeadline {
            end: Instant::now(),
        };
        for _ in 0..10 {
            assert_eq!(
                deadline.remaining().unwrap_err().kind(),
                io::ErrorKind::TimedOut
            );
        }
    }

    #[test]
    fn expired_socket_does_not_read_ready_bytes_or_send_new_bytes() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let mut sender = TcpStream::connect(listener.local_addr().unwrap()).unwrap();
        let (stream, _) = listener.accept().unwrap();
        sender.write_all(b"already buffered").unwrap();
        let mut bounded = DeadlineTcpStream {
            stream,
            deadline: NetworkDeadline {
                end: Instant::now(),
            },
        };
        let mut buffer = [0_u8; 32];
        assert_eq!(
            bounded.read(&mut buffer).unwrap_err().kind(),
            io::ErrorKind::TimedOut
        );
        assert_eq!(
            bounded.write(b"must not be sent").unwrap_err().kind(),
            io::ErrorKind::TimedOut
        );
        assert_eq!(bounded.flush().unwrap_err().kind(), io::ErrorKind::TimedOut);
        assert_eq!(buffer, [0; 32]);
        sender
            .set_read_timeout(Some(Duration::from_secs(5)))
            .unwrap();
        bounded.shutdown(Shutdown::Write).unwrap();
        assert_eq!(sender.read(&mut buffer).unwrap(), 0);
    }

    #[test]
    fn expired_deadline_rejects_connect_before_the_socket_is_opened() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        listener.set_nonblocking(true).unwrap();
        let error = DeadlineTcpStream::connect(
            &listener.local_addr().unwrap(),
            NetworkDeadline {
                end: Instant::now(),
            },
        )
        .unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::TimedOut);
        assert_eq!(
            listener.accept().unwrap_err().kind(),
            io::ErrorKind::WouldBlock
        );
    }
    #[test]
    fn refused_first_address_falls_back_without_repeating_payload() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let live = listener.local_addr().unwrap();
        let refused = "127.0.0.1:0".parse().unwrap();
        let deadline = NetworkDeadline::new(Duration::from_secs(5)).unwrap();
        let mut connected = DeadlineTcpStream::connect_addresses(
            &[refused, live],
            deadline,
            TcpStream::connect_timeout,
        )
        .unwrap();
        assert_eq!(connected.deadline.end, deadline.end);
        let (mut peer, _) = listener.accept().unwrap();
        peer.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
        connected.write_all(b"exactly once").unwrap();
        connected.shutdown(Shutdown::Write).unwrap();
        let mut observed = Vec::new();
        peer.read_to_end(&mut observed).unwrap();
        assert_eq!(observed, b"exactly once");
        listener.set_nonblocking(true).unwrap();
        assert_eq!(
            listener.accept().unwrap_err().kind(),
            io::ErrorKind::WouldBlock
        );
    }

    #[test]
    fn connection_attempts_share_the_remaining_budget_and_stop_at_success() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let live = listener.local_addr().unwrap();
        let first = "127.0.0.1:0".parse().unwrap();
        let deadline = NetworkDeadline::new(Duration::from_secs(6)).unwrap();
        let mut calls = Vec::new();
        let mut timeouts = Vec::new();
        let stream = DeadlineTcpStream::connect_addresses(
            &[first, live, first],
            deadline,
            |address, timeout| {
                calls.push(*address);
                timeouts.push(timeout);
                if *address == first {
                    Err(io::Error::new(
                        io::ErrorKind::ConnectionRefused,
                        "injected first dial refusal",
                    ))
                } else {
                    TcpStream::connect_timeout(address, timeout)
                }
            },
        )
        .unwrap();
        assert_eq!(calls, vec![first, live]);
        assert!(timeouts[0] <= Duration::from_secs(2));
        assert!(timeouts[1] <= Duration::from_secs(3));
        assert_eq!(
            stream.deadline.end, deadline.end,
            "DNS/dial budget is not renewed for I/O"
        );
    }

    #[test]
    fn exhausted_deadline_stops_before_trying_any_destination() {
        let address = "127.0.0.1:80".parse().unwrap();
        let error = DeadlineTcpStream::connect_addresses(
            &[address, address],
            NetworkDeadline {
                end: Instant::now(),
            },
            |_, _| panic!("deadline exhaustion must precede the first socket"),
        )
        .unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::TimedOut);
    }

    #[test]
    fn empty_and_failed_address_lists_return_errors_without_a_stream() {
        let deadline = NetworkDeadline::new(Duration::from_secs(5)).unwrap();
        let error = DeadlineTcpStream::connect_addresses(&[], deadline, |_, _| {
            panic!("empty list must not dial")
        })
        .unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::NotFound);
        let address = "127.0.0.1:0".parse().unwrap();
        let mut attempts = 0;
        let error = DeadlineTcpStream::connect_addresses(&[address, address], deadline, |_, _| {
            attempts += 1;
            Err(io::Error::new(
                io::ErrorKind::ConnectionRefused,
                "injected refusal",
            ))
        })
        .unwrap_err();
        assert_eq!(attempts, 2);
        assert_eq!(error.kind(), io::ErrorKind::ConnectionRefused);
    }
}

#[cfg(test)]
mod pinned_tests {
    use super::super::{
        HostIoCapability, HostIoError, HostIoRequest, HostIoResponse, SandboxedHostIo,
    };
    use super::*;
    use std::net::TcpListener;
    use std::sync::Arc;

    fn request(host: &str, port: u16, use_tls: bool) -> HostIoRequest {
        HostIoRequest::NetworkRequest {
            endpoint: format!("{host}:{port}"),
            payload: format!("GET / HTTP/1.1\r\nHost: {host}\r\nConnection: keep-alive\r\n\r\n")
                .into_bytes(),
            max_len: 4096,
            use_tls,
        }
    }

    fn serve(
        listener: TcpListener,
        key: &rcgen::CertifiedKey,
    ) -> std::thread::JoinHandle<(Option<String>, Vec<u8>)> {
        use rustls_pki_types::{PrivateKeyDer, PrivatePkcs8KeyDer};
        let config = rustls::ServerConfig::builder_with_provider(Arc::new(
            rustls::crypto::ring::default_provider(),
        ))
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_no_client_auth()
        .with_single_cert(
            vec![key.cert.der().clone()],
            PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(key.key_pair.serialize_der())),
        )
        .unwrap();
        listener.set_nonblocking(true).unwrap();
        std::thread::spawn(move || {
            let end = Instant::now() + Duration::from_secs(5);
            let socket = loop {
                match listener.accept() {
                    Ok((socket, _)) => break socket,
                    Err(error)
                        if error.kind() == io::ErrorKind::WouldBlock && Instant::now() < end =>
                    {
                        std::thread::sleep(Duration::from_millis(1));
                    }
                    other => panic!("bounded TLS accept failed: {other:?}"),
                }
            };
            socket
                .set_read_timeout(Some(Duration::from_secs(2)))
                .unwrap();
            socket
                .set_write_timeout(Some(Duration::from_secs(2)))
                .unwrap();
            let connection = rustls::ServerConnection::new(Arc::new(config)).unwrap();
            let mut tls = rustls::StreamOwned::new(connection, socket);
            let mut bytes = Vec::new();
            let mut byte = [0_u8; 1];
            while bytes.len() < 8192 && !bytes.ends_with(b"\r\n\r\n") {
                match tls.read(&mut byte) {
                    Ok(1) => bytes.push(byte[0]),
                    _ => return (tls.conn.server_name().map(str::to_owned), bytes),
                }
            }
            let name = tls.conn.server_name().map(str::to_owned);
            let _ = tls.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok");
            let _ = tls.flush();
            // Deliberately no close_notify: framed HTTP completion is sufficient.
            (name, bytes)
        })
    }

    #[test]
    fn pinned_https_authenticates_original_name_and_preserves_wire_bytes() {
        let root = tempfile::tempdir().unwrap();
        let key = rcgen::generate_simple_self_signed(vec!["service.invalid".into()]).unwrap();
        let provider = SandboxedHostIo::with_root(root.path())
            .unwrap()
            .with_extra_tls_roots_pem(key.cert.pem().as_bytes())
            .unwrap();
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let server = serve(listener, &key);
        let request = request("service.invalid", address.port(), true);
        let result = provider.perform_pinned_network(
            &request,
            &[HostIoCapability::NetworkSend],
            address,
            Instant::now() + Duration::from_secs(5),
        );
        let (sni, observed) = server.join().unwrap();
        assert_eq!(sni.as_deref(), Some("service.invalid"));
        let HostIoRequest::NetworkRequest { payload, .. } = request else {
            unreachable!()
        };
        assert_eq!(observed, payload);
        assert_eq!(
            result,
            Ok(HostIoResponse::NetworkRequest {
                response: b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok".to_vec(),
            })
        );
    }

    #[test]
    fn untrusted_and_wrong_name_certificates_never_receive_http_plaintext() {
        for (cert_name, trusted) in [("service.invalid", false), ("other.invalid", true)] {
            let root = tempfile::tempdir().unwrap();
            let key = rcgen::generate_simple_self_signed(vec![cert_name.into()]).unwrap();
            let mut provider = SandboxedHostIo::with_root(root.path()).unwrap();
            if trusted {
                provider = provider
                    .with_extra_tls_roots_pem(key.cert.pem().as_bytes())
                    .unwrap();
            }
            let listener = TcpListener::bind("127.0.0.1:0").unwrap();
            let address = listener.local_addr().unwrap();
            let server = serve(listener, &key);
            let result = provider.perform_pinned_network(
                &request("service.invalid", address.port(), true),
                &[HostIoCapability::NetworkSend],
                address,
                Instant::now() + Duration::from_secs(5),
            );
            let (_, observed) = server.join().unwrap();
            assert!(result.is_err(), "{cert_name} trusted={trusted}");
            assert!(
                observed.is_empty(),
                "HTTP payload escaped before TLS authentication"
            );
        }
    }

    #[test]
    fn pinned_ip_tls_uses_ip_certificate_identity_without_sni() {
        let root = tempfile::tempdir().unwrap();
        let key = rcgen::generate_simple_self_signed(vec!["127.0.0.1".into()]).unwrap();
        let provider = SandboxedHostIo::with_root(root.path())
            .unwrap()
            .with_extra_tls_roots_pem(key.cert.pem().as_bytes())
            .unwrap();
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let server = serve(listener, &key);
        let result = provider.perform_pinned_network(
            &request("127.0.0.1", address.port(), true),
            &[HostIoCapability::NetworkSend],
            address,
            Instant::now() + Duration::from_secs(5),
        );
        let (sni, observed) = server.join().unwrap();
        assert!(result.is_ok(), "{result:?}");
        assert!(sni.is_none());
        assert!(!observed.is_empty());
    }

    #[test]
    fn authority_capability_budget_and_payload_fail_before_connecting() {
        let root = tempfile::tempdir().unwrap();
        let mut provider = SandboxedHostIo::with_root(root.path()).unwrap();
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        listener.set_nonblocking(true).unwrap();
        let address = listener.local_addr().unwrap();
        let future = Instant::now() + Duration::from_secs(5);
        let good = request("service.invalid", address.port(), true);
        assert!(matches!(
            provider.perform_pinned_network(&good, &[], address, future),
            Err(HostIoError::CapabilityMissing { .. })
        ));
        assert!(
            provider
                .perform_pinned_network(
                    &good,
                    &[HostIoCapability::NetworkSend],
                    address,
                    Instant::now()
                )
                .is_err()
        );
        let wrong_port = if address.port() == 1 { 2 } else { 1 };
        for bad in [
            request("service.invalid", wrong_port, true),
            request("127.0.0.2", address.port(), true),
        ] {
            assert!(
                provider
                    .perform_pinned_network(&bad, &[HostIoCapability::NetworkSend], address, future)
                    .is_err()
            );
        }
        provider.max_bytes = 1;
        assert!(
            provider
                .perform_pinned_network(&good, &[HostIoCapability::NetworkSend], address, future)
                .is_err()
        );
        let local = HostIoRequest::FsWrite {
            path: "must-not-exist".into(),
            data: vec![],
        };
        assert!(
            provider
                .perform_pinned_network(&local, &[HostIoCapability::FsWrite], address, future)
                .is_err()
        );
        assert!(!root.path().join("must-not-exist").exists());
        assert_eq!(
            listener.accept().unwrap_err().kind(),
            io::ErrorKind::WouldBlock
        );
    }

    #[test]
    fn public_resolution_api_keeps_the_caller_deadline_for_numeric_inputs() {
        let endpoint = "127.0.0.1:80";
        assert_eq!(
            SandboxedHostIo::resolve_network_endpoint_until(
                endpoint,
                Instant::now() + Duration::from_secs(5)
            )
            .unwrap(),
            vec![endpoint.parse::<SocketAddr>().unwrap()]
        );
        assert_eq!(
            SandboxedHostIo::resolve_network_endpoint_until(endpoint, Instant::now())
                .unwrap_err()
                .kind(),
            io::ErrorKind::TimedOut
        );
    }
}
