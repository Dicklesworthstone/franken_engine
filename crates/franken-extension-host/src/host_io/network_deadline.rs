//! One absolute budget for DNS and the socket portion of a host network effect.
//!
//! A per-read timeout alone lets a slow peer retain the interpreter forever by
//! delivering occasional bytes. Keeping the deadline underneath rustls also
//! bounds handshake loops and TLS records that produce no application bytes.

use super::control::OperationControl;
use super::{HostIoControl, UnrestrictedHostIoControl};
use std::io::{self, Read, Write};
use std::net::{Shutdown, SocketAddr, TcpStream};
use std::sync::Arc;
use std::time::{Duration, Instant};

#[cfg(unix)]
mod connection_race;
mod resolver;
mod revocation;
pub use revocation::NetworkRevocation;
use revocation::REVOCATION_POLL_INTERVAL;

#[derive(Debug, Clone)]
pub(super) struct NetworkDeadline {
    end: Instant,
    revocation: Option<NetworkRevocation>,
    control: Option<OperationControl>,
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
            .map(Self::at)
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "network timeout overflow"))
    }

    fn at(end: Instant) -> Self {
        Self {
            end,
            revocation: None,
            control: None,
        }
    }

    fn remaining(&self) -> io::Result<Duration> {
        if let Some(revocation) = &self.revocation {
            revocation.check()?;
        }
        if let Some(control) = &self.control {
            control.check_io()?;
        }
        self.end
            .checked_duration_since(Instant::now())
            .filter(|remaining| !remaining.is_zero())
            .ok_or_else(|| {
                io::Error::new(io::ErrorKind::TimedOut, "network effect deadline exceeded")
            })
    }
    fn wait_slice(&self) -> io::Result<Duration> {
        let remaining = self.remaining()?;
        Ok(if self.revocation.is_some() || self.control.is_some() {
            remaining.min(REVOCATION_POLL_INTERVAL)
        } else {
            remaining
        })
    }

    pub(super) fn with_control(mut self, control: OperationControl) -> Self {
        self.control = Some(control);
        self
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
    /// Resolve once, retaining the resolver's first-family preference. Unix
    /// races at most two owned sockets with staggered starts; other platforms
    /// use bounded sequential failover. Neither path renews the shared budget
    /// or sends guest bytes before selecting a connection.
    pub(super) fn connect_endpoint(endpoint: &str, deadline: NetworkDeadline) -> io::Result<Self> {
        let addresses = resolver::resolve_endpoint(endpoint, deadline.clone())?;
        Self::connect_approved_addresses(&addresses, deadline)
    }

    /// Consume only an already-resolved, validated set. Unlike connect_endpoint,
    /// this cannot consult DNS or add any address beyond the approved list.
    fn connect_approved_addresses(
        addresses: &[SocketAddr],
        deadline: NetworkDeadline,
    ) -> io::Result<Self> {
        if addresses.len() == 1 {
            return Self::connect(&addresses[0], deadline);
        }
        #[cfg(unix)]
        {
            let stream = connection_race::connect_addresses(addresses, deadline.clone())?;
            Ok(Self { stream, deadline })
        }
        #[cfg(not(unix))]
        {
            Self::connect_addresses(addresses, deadline, TcpStream::connect_timeout)
        }
    }

    #[cfg(any(not(unix), test))]
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
        deadline.remaining()?;
        // Numeric/pinned requests need the same revocation checkpoints as
        // dual-stack races, not an uninterruptible single-address connect.
        #[cfg(unix)]
        let stream = connection_race::connect_addresses(&[*address], deadline.clone())?;
        #[cfg(not(unix))]
        let stream = TcpStream::connect_timeout(address, deadline.remaining()?)?;
        // A late success must not start a fresh budget for the request body.
        deadline.remaining()?;
        Ok(Self { stream, deadline })
    }

    pub(super) fn shutdown(&self, how: Shutdown) -> io::Result<()> {
        self.stream.shutdown(how)
    }

    pub(super) fn check_active(&self) -> io::Result<()> {
        self.deadline.remaining().map(|_| ())
    }

    fn retry_io<T>(
        &mut self,
        mut attempt: impl FnMut(&mut TcpStream, Duration) -> io::Result<T>,
    ) -> io::Result<T> {
        loop {
            let timeout = self.deadline.wait_slice()?;
            match attempt(&mut self.stream, timeout) {
                // Preserve Read/Write's progress contract: Err must not hide
                // a successful partial write and cause a caller to resend it.
                // The next I/O and the enclosing host completion boundary
                // check revocation/deadline again, including buffered TLS EOF.
                Ok(value) => return Ok(value),
                Err(error) => {
                    self.deadline.remaining()?;
                    if matches!(
                        error.kind(),
                        io::ErrorKind::WouldBlock
                            | io::ErrorKind::TimedOut
                            | io::ErrorKind::Interrupted
                    ) {
                        continue;
                    }
                    return Err(error);
                }
            }
        }
    }
}

impl Read for DeadlineTcpStream {
    fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
        if buffer.is_empty() {
            return Ok(0);
        }
        self.retry_io(|stream, timeout| {
            stream.set_read_timeout(Some(timeout))?;
            stream.read(buffer)
        })
    }
}

impl Write for DeadlineTcpStream {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        if bytes.is_empty() {
            return Ok(0);
        }
        self.retry_io(|stream, timeout| {
            stream.set_write_timeout(Some(timeout))?;
            stream.write(bytes)
        })
    }

    fn flush(&mut self) -> io::Result<()> {
        self.deadline.remaining()?;
        let result = self.stream.flush();
        self.deadline.remaining()?;
        result
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

    /// Obtain this provider's irreversible network kill switch. Provider
    /// clones and timeout builders retain the same scope; a fresh provider
    /// establishes independent authority. No guest can reset this signal.
    #[must_use]
    pub fn network_revocation(&self) -> NetworkRevocation {
        self.network_revocation.clone()
    }

    pub(super) fn network_deadline(&self) -> io::Result<NetworkDeadline> {
        let mut deadline = NetworkDeadline::new(self.network_timeout)?;
        deadline.revocation = Some(self.network_revocation.clone());
        deadline.remaining()?;
        Ok(deadline)
    }

    /// Resolve for subsequent product-policy approval under this provider's
    /// revocation scope. Neither this call nor its DNS worker opens a socket.
    /// Use this instead of the unscoped static resolver when containment must
    /// interrupt DNS waiting as well as the later pinned network operation.
    pub fn resolve_network_endpoint_scoped_until(
        &self,
        endpoint: &str,
        end: Instant,
    ) -> io::Result<Vec<SocketAddr>> {
        let mut deadline = self.network_deadline()?;
        deadline.end = deadline.end.min(end);
        resolver::resolve_endpoint(endpoint, deadline)
    }

    /// Resolve inside one execution without revoking a shared provider. The
    /// product must still authorize every returned address before pinned I/O.
    pub fn resolve_network_endpoint_controlled_until(
        &self,
        endpoint: &str,
        end: Instant,
        control: Arc<dyn HostIoControl>,
    ) -> io::Result<Vec<SocketAddr>> {
        let control = OperationControl::new(control);
        control.check_io()?;
        let mut deadline = self.network_deadline()?.with_control(control);
        deadline.end = deadline.end.min(end);
        resolver::resolve_endpoint(endpoint, deadline)
    }

    /// Resolve with the engine's process-wide admission limit and an absolute
    /// caller deadline. A timed-out OS call keeps its worker permit until it
    /// exits. No resolver worker can open a connection or perform a guest effect.
    /// The product must check the returned addresses against its egress policy.
    pub fn resolve_network_endpoint_until(
        endpoint: &str,
        deadline: Instant,
    ) -> io::Result<Vec<SocketAddr>> {
        resolver::resolve_endpoint(endpoint, NetworkDeadline::at(deadline))
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
        self.perform_pinned_network_candidates(request, granted, &[destination], deadline)
    }

    /// Connect to the first reachable member of an entirely policy-approved
    /// address set. Every candidate is validated before the first socket, and
    /// duplicates are removed without changing preference order. Unix reuses
    /// the owned, two-socket staggered race; other platforms use sequential
    /// failover. Both keep the remaining absolute budget, and losing sockets
    /// are closed before application/TLS work starts on the selected stream.
    ///
    /// Failover ends at the first successful TCP connection. TLS authentication,
    /// writes and reads execute once: failures after connecting NEVER redial a
    /// second server or replay application bytes. The original authority is
    /// retained for SNI and certificate verification, with no new DNS lookup.
    /// The caller must authorize every destination, not just the first one.
    pub fn perform_pinned_network_candidates(
        &self,
        request: &super::HostIoRequest,
        granted: &[super::HostIoCapability],
        destinations: &[SocketAddr],
        deadline: Instant,
    ) -> super::HostIoOutcome {
        self.perform_pinned_network_candidates_controlled(
            request,
            granted,
            destinations,
            deadline,
            Arc::new(UnrestrictedHostIoControl),
        )
    }

    /// Policy-approved destinations with operation-local execution control.
    /// Controls survive DNS-free connection selection, TLS and response waits;
    /// no failure retries application bytes or mutates provider-wide revocation.
    pub fn perform_pinned_network_candidates_controlled(
        &self,
        request: &super::HostIoRequest,
        granted: &[super::HostIoCapability],
        destinations: &[SocketAddr],
        deadline: Instant,
        control: Arc<dyn HostIoControl>,
    ) -> super::HostIoOutcome {
        use super::{HostIoError, HostIoRequest};

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
        self.run_controlled_network(control, |mut scoped| {
            scoped.end = scoped.end.min(deadline);
            self.perform_pinned_network_admitted(request, endpoint, payload, destinations, scoped)
        })
    }

    fn perform_pinned_network_admitted(
        &self,
        request: &super::HostIoRequest,
        endpoint: &str,
        payload: Option<&[u8]>,
        destinations: &[SocketAddr],
        deadline: NetworkDeadline,
    ) -> super::HostIoOutcome {
        use super::{HostIoError, HostIoRequest, HostIoResponse};

        let fail = |error: io::Error| HostIoError::Io {
            detail: format!("pinned network {endpoint}: {error}"),
        };
        if destinations.is_empty() || destinations.len() > 64 {
            return Err(HostIoError::SandboxViolation {
                detail: "pinned network requires between 1 and 64 approved addresses".to_string(),
            });
        }
        let identity = pinned_identity(endpoint, destinations[0]).map_err(fail)?;
        let mut unique = Vec::with_capacity(destinations.len());
        for &destination in destinations {
            // Validate the whole set before dialing. A mismatched later port
            // or numeric identity must not leave an earlier side effect behind.
            pinned_identity(endpoint, destination).map_err(fail)?;
            if !unique.contains(&destination) {
                unique.push(destination);
            }
        }
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
            // Only TCP connection failures can advance through approved IPs.
            // Once a socket exists, no TLS or HTTP failure can trigger a retry.
            let socket = DeadlineTcpStream::connect_approved_addresses(&unique, deadline.clone())
                .map_err(fail)?;
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

        let mut stream = DeadlineTcpStream::connect_approved_addresses(&unique, deadline.clone())
            .map_err(fail)?;
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
        let deadline = NetworkDeadline::at(Instant::now());
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
            deadline: NetworkDeadline::at(Instant::now()),
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
            NetworkDeadline::at(Instant::now()),
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
            deadline.clone(),
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
            deadline.clone(),
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
            NetworkDeadline::at(Instant::now()),
            |_, _| panic!("deadline exhaustion must precede the first socket"),
        )
        .unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::TimedOut);
    }

    #[test]
    fn empty_and_failed_address_lists_return_errors_without_a_stream() {
        let deadline = NetworkDeadline::new(Duration::from_secs(5)).unwrap();
        let error = DeadlineTcpStream::connect_addresses(&[], deadline.clone(), |_, _| {
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
    fn approved_candidates_fail_over_before_tls_and_preserve_original_identity() {
        for bind in ["127.0.0.1:0", "[::1]:0"] {
            let root = tempfile::tempdir().unwrap();
            let key = rcgen::generate_simple_self_signed(vec!["service.invalid".into()]).unwrap();
            let provider = SandboxedHostIo::with_root(root.path())
                .unwrap()
                .with_extra_tls_roots_pem(key.cert.pem().as_bytes())
                .unwrap();
            let listener = TcpListener::bind(bind).unwrap();
            let live = listener.local_addr().unwrap();
            let unavailable = SocketAddr::new("127.0.0.2".parse().unwrap(), live.port());
            let server = serve(listener, &key);
            let request = request("service.invalid", live.port(), true);
            let result = provider.perform_pinned_network_candidates(
                &request,
                &[HostIoCapability::NetworkSend],
                &[unavailable, live, live],
                Instant::now() + Duration::from_secs(5),
            );
            let (sni, received) = server.join().unwrap();
            assert!(result.is_ok(), "{bind}: {result:?}");
            assert_eq!(sni.as_deref(), Some("service.invalid"));
            let HostIoRequest::NetworkRequest { payload, .. } = request else {
                unreachable!()
            };
            assert_eq!(received, payload);
        }
    }

    #[test]
    fn candidate_validation_is_all_or_nothing_before_any_socket() {
        let root = tempfile::tempdir().unwrap();
        let provider = SandboxedHostIo::with_root(root.path()).unwrap();
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        listener.set_nonblocking(true).unwrap();
        let live = listener.local_addr().unwrap();
        let wrong_port = SocketAddr::new(live.ip(), if live.port() == 1 { 2 } else { 1 });
        let request = request("service.invalid", live.port(), true);
        let deadline = Instant::now() + Duration::from_secs(5);
        for candidates in [vec![], vec![live; 65], vec![live, wrong_port]] {
            assert!(
                provider
                    .perform_pinned_network_candidates(
                        &request,
                        &[HostIoCapability::NetworkSend],
                        &candidates,
                        deadline
                    )
                    .is_err()
            );
        }
        let literal = self::request("127.0.0.1", live.port(), true);
        let wrong_ip = SocketAddr::new("127.0.0.2".parse().unwrap(), live.port());
        assert!(
            provider
                .perform_pinned_network_candidates(
                    &literal,
                    &[HostIoCapability::NetworkSend],
                    &[live, wrong_ip],
                    deadline
                )
                .is_err()
        );
        assert!(matches!(
            provider.perform_pinned_network_candidates(&request, &[], &[live], deadline),
            Err(HostIoError::CapabilityMissing { .. })
        ));
        assert!(
            provider
                .perform_pinned_network_candidates(
                    &request,
                    &[HostIoCapability::NetworkSend],
                    &[live],
                    Instant::now()
                )
                .is_err()
        );
        assert_eq!(
            listener.accept().unwrap_err().kind(),
            io::ErrorKind::WouldBlock
        );
    }

    #[test]
    fn tls_authentication_failure_never_advances_to_a_second_approved_server() {
        let root = tempfile::tempdir().unwrap();
        let key = rcgen::generate_simple_self_signed(vec!["wrong.invalid".into()]).unwrap();
        let provider = SandboxedHostIo::with_root(root.path())
            .unwrap()
            .with_extra_tls_roots_pem(key.cert.pem().as_bytes())
            .unwrap();
        let first = TcpListener::bind("127.0.0.1:0").unwrap();
        let first_address = first.local_addr().unwrap();
        let second = TcpListener::bind(SocketAddr::new(
            "127.0.0.2".parse().unwrap(),
            first_address.port(),
        ))
        .unwrap();
        second.set_nonblocking(true).unwrap();
        let second_address = second.local_addr().unwrap();
        let server = serve(first, &key);
        let result = provider.perform_pinned_network_candidates(
            &request("service.invalid", first_address.port(), true),
            &[HostIoCapability::NetworkSend],
            &[first_address, second_address],
            Instant::now() + Duration::from_secs(5),
        );
        let (_, received) = server.join().unwrap();
        assert!(result.is_err());
        assert!(received.is_empty());
        assert_eq!(
            second.accept().unwrap_err().kind(),
            io::ErrorKind::WouldBlock
        );
    }

    #[test]
    fn pre_send_failover_applies_to_raw_send_receive_and_plaintext_http() {
        let root = tempfile::tempdir().unwrap();
        let provider = SandboxedHostIo::with_root(root.path()).unwrap();
        for kind in 0..3 {
            let listener = TcpListener::bind("127.0.0.1:0").unwrap();
            listener.set_nonblocking(true).unwrap();
            let live = listener.local_addr().unwrap();
            let unavailable = SocketAddr::new("127.0.0.2".parse().unwrap(), live.port());
            let endpoint = format!("service.invalid:{}", live.port());
            let request = match kind {
                0 => HostIoRequest::NetworkSend {
                    endpoint,
                    payload: b"exactly once".to_vec(),
                },
                1 => HostIoRequest::NetworkRecv {
                    endpoint,
                    max_len: 4096,
                },
                _ => self::request("service.invalid", live.port(), false),
            };
            let server = std::thread::spawn(move || {
                let end = Instant::now() + Duration::from_secs(5);
                let mut socket = loop {
                    match listener.accept() {
                        Ok((socket, _)) => break socket,
                        Err(error)
                            if error.kind() == io::ErrorKind::WouldBlock
                                && Instant::now() < end =>
                        {
                            std::thread::sleep(Duration::from_millis(1));
                        }
                        other => panic!("bounded accept: {other:?}"),
                    }
                };
                socket
                    .set_read_timeout(Some(Duration::from_secs(2)))
                    .unwrap();
                socket
                    .set_write_timeout(Some(Duration::from_secs(2)))
                    .unwrap();
                let mut received = Vec::new();
                if kind != 1 {
                    socket.read_to_end(&mut received).unwrap();
                }
                if kind == 1 {
                    socket.write_all(b"raw response").unwrap();
                }
                if kind == 2 {
                    socket
                        .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok")
                        .unwrap();
                }
                received
            });
            let result = provider.perform_pinned_network_candidates(
                &request,
                &[request.required_capability()],
                &[unavailable, live, live],
                Instant::now() + Duration::from_secs(5),
            );
            let received = server.join().unwrap();
            assert!(result.is_ok(), "{kind}: {result:?}");
            match request {
                HostIoRequest::NetworkSend { payload, .. }
                | HostIoRequest::NetworkRequest { payload, .. } => assert_eq!(received, payload),
                HostIoRequest::NetworkRecv { .. } => assert_eq!(
                    result,
                    Ok(HostIoResponse::NetworkRecv {
                        bytes: b"raw response".to_vec()
                    })
                ),
                _ => unreachable!(),
            }
        }
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
