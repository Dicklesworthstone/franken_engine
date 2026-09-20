//! Real loopback TCP/TLS regressions for HTTP response framing.
//!
//! These exercise the production provider and journal protocol, not a mocked
//! transport. A held-open server closes only after the provider returns; the
//! channel deadline is a deadlock guard, not a performance assertion.

#![forbid(unsafe_code)]

use frankenengine_extension_host::host_effect_journal::{
    HostEffectJournalEntry, InMemoryHostEffectJournal,
};
use frankenengine_extension_host::host_io::{
    HostIoCapability, HostIoError, HostIoOutcome, HostIoProvider, HostIoRequest, HostIoResponse,
    SandboxedHostIo,
};
use std::io::{Read, Write};
use std::net::TcpListener;
use std::sync::{Arc, mpsc};
use std::time::Duration;

const FIXED: &[u8] = b"HTTP/1.1 200 OK\r\nContent-Length: 4\r\n\r\nbody";
const CHUNKED: &[u8] = b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n2\r\n\x00\xff\r\n2\r\nok\r\n0\r\nX-Checksum: abc\r\n\r\n";
const TRUNCATED: &[u8] = b"HTTP/1.1 200 OK\r\nContent-Length: 9\r\n\r\nshort";
const CLOSE_DELIMITED: &[u8] = b"HTTP/1.1 200 OK\r\n\r\nbody";

// Both the accept and the held-open phase are bounded even when the provider
// fails before connecting. A failed assertion must not strand a test server.
fn accept_revocation_peer(listener: &TcpListener) -> std::net::TcpStream {
    listener.set_nonblocking(true).unwrap();
    let end = std::time::Instant::now() + Duration::from_secs(5);
    loop {
        match listener.accept() {
            Ok((stream, _)) => {
                stream
                    .set_read_timeout(Some(Duration::from_secs(5)))
                    .unwrap();
                stream
                    .set_write_timeout(Some(Duration::from_secs(5)))
                    .unwrap();
                return stream;
            }
            Err(error)
                if error.kind() == std::io::ErrorKind::WouldBlock
                    && std::time::Instant::now() < end =>
            {
                std::thread::sleep(Duration::from_millis(1))
            }
            other => panic!("revocation test accept failed: {other:?}"),
        }
    }
}

fn hold_after_request<S: Read>(
    stream: &mut S,
    ready: &mpsc::SyncSender<()>,
    release: &mpsc::Receiver<()>,
) -> Vec<u8> {
    let mut request = Vec::new();
    let mut byte = [0; 1];
    while !request.ends_with(b"\r\n\r\n") {
        stream.read_exact(&mut byte).unwrap();
        request.push(byte[0]);
        assert!(request.len() <= 8192);
    }
    ready.send(()).unwrap();
    // No response or EOF can explain the client's completion until the test
    // releases this server after observing the revocation outcome.
    let _ = release.recv_timeout(Duration::from_secs(5));
    request
}

#[test]
fn revocation_interrupts_tcp_and_tls_response_waits_and_replays_the_denial() {
    for use_tls in [false, true] {
        for pinned in [false, true] {
            let directory = tempfile::tempdir().unwrap();
            let provider = SandboxedHostIo::with_root(directory.path())
                .unwrap()
                .with_network_timeout(Duration::from_secs(10))
                .unwrap();
            let (provider, tls_config) = install_loopback_tls(provider);
            let signal = provider.network_revocation();
            let listener = TcpListener::bind("127.0.0.1:0").unwrap();
            let address = listener.local_addr().unwrap();
            let (ready, wait_ready) = mpsc::sync_channel(1);
            let (release, wait_release) = mpsc::sync_channel(1);
            let server = std::thread::spawn(move || {
                let mut tcp = accept_revocation_peer(&listener);
                if use_tls {
                    let connection = rustls::ServerConnection::new(tls_config).unwrap();
                    let mut tls = rustls::StreamOwned::new(connection, tcp);
                    hold_after_request(&mut tls, &ready, &wait_release)
                } else {
                    hold_after_request(&mut tcp, &ready, &wait_release)
                }
            });
            let payload = b"GET /once HTTP/1.1\r\nHost: loopback\r\n\r\n".to_vec();
            let request = HostIoRequest::NetworkRequest {
                endpoint: address.to_string(),
                payload: payload.clone(),
                max_len: 4096,
                use_tls,
            };
            let journal = Arc::new(InMemoryHostEffectJournal::recording());
            journal.begin_execution().unwrap();
            let worker_journal = Arc::clone(&journal);
            let worker_request = request.clone();
            let (done, wait_done) = mpsc::sync_channel(1);
            let worker = std::thread::spawn(move || {
                let reservation = worker_journal.reserve_host_io(&worker_request).unwrap();
                let outcome = if pinned {
                    provider.perform_pinned_network_candidates(
                        &worker_request,
                        &[HostIoCapability::NetworkSend],
                        &[address, address],
                        std::time::Instant::now() + Duration::from_secs(10),
                    )
                } else {
                    provider.perform(&worker_request, &[HostIoCapability::NetworkSend])
                };
                worker_journal
                    .complete_host_io(reservation, &worker_request, &outcome)
                    .unwrap();
                done.send(outcome).unwrap();
            });
            let observed_request = wait_ready.recv_timeout(Duration::from_secs(5));
            signal.revoke();
            let result = wait_done.recv_timeout(Duration::from_secs(2));
            let _ = release.send(());
            worker.join().unwrap();
            let observed = server.join().unwrap();
            assert!(observed_request.is_ok());
            assert_eq!(observed, payload);
            let outcome =
                result.expect("revocation must not wait for the peer or ten-second deadline");
            assert!(
                matches!(&outcome, Err(HostIoError::Denied { .. })),
                "{outcome:?}"
            );
            let entries = journal.finish_execution().unwrap();
            assert_eq!(entries.len(), 1);
            let replay = InMemoryHostEffectJournal::replaying(entries.clone());
            replay.begin_execution().unwrap();
            assert_eq!(replay.replay_host_io(&request), Some(outcome));
            assert_eq!(replay.finish_execution().unwrap(), entries);
        }
    }
}

#[test]
fn revocation_interrupts_a_tls_handshake_with_no_http_payload_or_peer_close() {
    let directory = tempfile::tempdir().unwrap();
    let provider = SandboxedHostIo::with_root(directory.path())
        .unwrap()
        .with_network_timeout(Duration::from_secs(10))
        .unwrap();
    let signal = provider.network_revocation();
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let address = listener.local_addr().unwrap();
    let (ready, wait_ready) = mpsc::sync_channel(1);
    let (release, wait_release) = mpsc::sync_channel(1);
    let server = std::thread::spawn(move || {
        let mut peer = accept_revocation_peer(&listener);
        let mut header = [0; 5];
        peer.read_exact(&mut header).unwrap();
        ready.send(()).unwrap();
        let _ = wait_release.recv_timeout(Duration::from_secs(5));
        header
    });
    let (done, wait_done) = mpsc::sync_channel(1);
    let worker = std::thread::spawn(move || {
        let request = HostIoRequest::NetworkRequest {
            endpoint: address.to_string(),
            payload: b"GET /secret HTTP/1.1\r\n\r\n".to_vec(),
            max_len: 4096,
            use_tls: true,
        };
        done.send(provider.perform(&request, &[HostIoCapability::NetworkSend]))
            .unwrap();
    });
    let handshake_started = wait_ready.recv_timeout(Duration::from_secs(5));
    signal.revoke();
    let result = wait_done.recv_timeout(Duration::from_secs(2));
    let _ = release.send(());
    worker.join().unwrap();
    let header = server.join().unwrap();
    assert!(handshake_started.is_ok());
    assert_eq!(header[0], 22, "only a TLS handshake, never plaintext HTTP");
    assert!(matches!(result.unwrap(), Err(HostIoError::Denied { .. })));
}

struct Exchange {
    outcome: HostIoOutcome,
    request: HostIoRequest,
    entries: Vec<HostEffectJournalEntry>,
}

fn serve<S: Read + Write>(
    stream: &mut S,
    response: &[u8],
    hold_open: bool,
    release: &mpsc::Receiver<()>,
) -> (Vec<u8>, bool) {
    let mut request = Vec::new();
    let mut buffer = [0_u8; 1024];
    while !request.windows(4).any(|part| part == b"\r\n\r\n") {
        let count = stream.read(&mut buffer).expect("read real HTTP request");
        assert_ne!(count, 0, "request ended before its headers");
        request.extend_from_slice(&buffer[..count]);
        assert!(request.len() <= 16 * 1024, "test request must be bounded");
    }
    stream.write_all(response).expect("send real HTTP response");
    stream.flush().expect("flush real response");
    let released = !hold_open || release.recv_timeout(Duration::from_secs(5)).is_ok();
    (request, released)
}

fn install_loopback_tls(provider: SandboxedHostIo) -> (SandboxedHostIo, Arc<rustls::ServerConfig>) {
    let certified = rcgen::generate_simple_self_signed(vec!["127.0.0.1".to_string()])
        .expect("generate loopback TLS certificate");
    let provider = provider
        .with_extra_tls_roots_pem(certified.cert.pem().as_bytes())
        .expect("install explicit test trust anchor");
    let key = rustls_pki_types::PrivateKeyDer::Pkcs8(certified.key_pair.serialize_der().into());
    let crypto = Arc::new(rustls::crypto::ring::default_provider());
    let config = rustls::ServerConfig::builder_with_provider(crypto)
        .with_safe_default_protocol_versions()
        .expect("TLS versions")
        .with_no_client_auth()
        .with_single_cert(vec![certified.cert.der().clone()], key)
        .expect("TLS server certificate");
    (provider, Arc::new(config))
}

fn exchange(
    response: &[u8],
    use_tls: bool,
    hold_open: bool,
    close_notify: bool,
    method: &str,
    cap: u64,
) -> Exchange {
    let directory = tempfile::tempdir().expect("sandbox directory");
    let mut provider = SandboxedHostIo::with_root(directory.path()).expect("real provider");
    let tls_config = if use_tls {
        let (configured, config) = install_loopback_tls(provider);
        provider = configured;
        Some(config)
    } else {
        None
    };
    let listener = TcpListener::bind("127.0.0.1:0").expect("loopback listener");
    let endpoint = listener.local_addr().unwrap().to_string();
    let (release, receive_release) = mpsc::sync_channel(1);
    let response = response.to_vec();
    let server = std::thread::spawn(move || {
        let (mut tcp, _) = listener.accept().expect("accept loopback connection");
        tcp.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
        tcp.set_write_timeout(Some(Duration::from_secs(5))).unwrap();
        if let Some(config) = tls_config {
            let connection = rustls::ServerConnection::new(config).expect("TLS server");
            let mut tls = rustls::StreamOwned::new(connection, tcp);
            let observed = serve(&mut tls, &response, hold_open, &receive_release);
            if close_notify {
                tls.conn.send_close_notify();
                // A self-delimited response permits the client to leave first.
                // Close-notify writes can then legitimately see a closed socket.
                let _ = tls.flush();
            }
            observed
        } else {
            serve(&mut tcp, &response, hold_open, &receive_release)
        }
    });
    let payload = format!("{method} / HTTP/1.1\r\nHost: loopback\r\n\r\n").into_bytes();
    let request = HostIoRequest::NetworkRequest {
        endpoint,
        payload: payload.clone(),
        max_len: cap,
        use_tls,
    };
    let journal = InMemoryHostEffectJournal::recording();
    journal.begin_execution().unwrap();
    let reservation = journal.reserve_host_io(&request).unwrap();
    let outcome = provider.perform(&request, &[HostIoCapability::NetworkSend]);
    let _ = release.send(());
    let (observed, released) = server.join().expect("loopback server joins");
    assert_eq!(
        observed, payload,
        "exact request crossed the real connection"
    );
    assert!(
        released,
        "provider waited for socket closure instead of HTTP framing"
    );
    journal
        .complete_host_io(reservation, &request, &outcome)
        .unwrap();
    Exchange {
        outcome,
        request,
        entries: journal.finish_execution().unwrap(),
    }
}

#[test]
fn content_length_finishes_on_persistent_tcp_and_tls_connections() {
    for use_tls in [false, true] {
        let result = exchange(FIXED, use_tls, true, false, "GET", 4096);
        assert_eq!(
            result.outcome.unwrap(),
            HostIoResponse::NetworkRequest {
                response: FIXED.to_vec()
            }
        );
    }
}

#[test]
fn chunked_binary_payload_and_trailers_are_preserved_on_tcp_and_tls() {
    for use_tls in [false, true] {
        let result = exchange(CHUNKED, use_tls, true, false, "GET", 4096);
        assert_eq!(
            result.outcome.unwrap(),
            HostIoResponse::NetworkRequest {
                response: CHUNKED.to_vec()
            }
        );
    }
}

#[test]
fn informational_responses_do_not_end_the_real_round_trip() {
    let mut raw = b"HTTP/1.1 103 Early Hints\r\nLink: </x>\r\n\r\n".to_vec();
    raw.extend_from_slice(FIXED);
    for use_tls in [false, true] {
        let result = exchange(&raw, use_tls, true, false, "GET", 4096);
        assert_eq!(
            result.outcome.unwrap(),
            HostIoResponse::NetworkRequest {
                response: raw.clone()
            }
        );
    }
}

#[test]
fn head_and_bodyless_statuses_finish_without_reading_a_representation() {
    for use_tls in [false, true] {
        for (method, response) in [
            (
                "HEAD",
                &b"HTTP/1.1 200 OK\r\nContent-Length: 999999\r\n\r\n"[..],
            ),
            ("GET", b"HTTP/1.1 204 No Content\r\n\r\n"),
            (
                "GET",
                b"HTTP/1.1 304 Not Modified\r\nContent-Length: 999999\r\n\r\n",
            ),
        ] {
            let result = exchange(response, use_tls, true, false, method, 4096);
            assert_eq!(
                result.outcome.unwrap(),
                HostIoResponse::NetworkRequest {
                    response: response.to_vec()
                }
            );
        }
    }
}

#[test]
fn premature_close_is_not_a_successful_fixed_length_response() {
    for use_tls in [false, true] {
        for close_notify in [false, true] {
            let result = exchange(TRUNCATED, use_tls, false, close_notify, "GET", 4096);
            assert!(matches!(result.outcome, Err(HostIoError::Io { .. })));
        }
    }
}

#[test]
fn tls_close_delimited_response_requires_authenticated_close_notification() {
    let complete = exchange(CLOSE_DELIMITED, true, false, true, "GET", 4096);
    assert_eq!(
        complete.outcome.unwrap(),
        HostIoResponse::NetworkRequest {
            response: CLOSE_DELIMITED.to_vec()
        }
    );
    let truncated = exchange(CLOSE_DELIMITED, true, false, false, "GET", 4096);
    assert!(matches!(truncated.outcome, Err(HostIoError::Io { .. })));
}

#[test]
fn tls_fixed_and_chunked_messages_need_no_close_notification_after_completion() {
    for response in [FIXED, CHUNKED] {
        let result = exchange(response, true, false, false, "GET", 4096);
        assert_eq!(
            result.outcome.unwrap(),
            HostIoResponse::NetworkRequest {
                response: response.to_vec()
            }
        );
    }
}

#[test]
fn wire_cap_accepts_exact_boundary_and_rejects_oversize_before_waiting_for_body() {
    for use_tls in [false, true] {
        let exact = exchange(FIXED, use_tls, true, false, "GET", FIXED.len() as u64);
        assert!(exact.outcome.is_ok());
        let too_small = exchange(FIXED, use_tls, true, false, "GET", FIXED.len() as u64 - 1);
        assert!(matches!(too_small.outcome, Err(HostIoError::Io { .. })));
        let declared = b"HTTP/1.1 200 OK\r\nContent-Length: 999999\r\n\r\n";
        let too_large = exchange(declared, use_tls, true, false, "GET", 4096);
        assert!(matches!(too_large.outcome, Err(HostIoError::Io { .. })));
    }
}

#[test]
fn ambiguous_lengths_and_incomplete_chunks_fail_closed_on_real_connections() {
    for use_tls in [false, true] {
        for response in [
            &b"HTTP/1.1 200 OK\r\nContent-Length: 4\r\nContent-Length: 5\r\n\r\nbody"[..],
            b"HTTP/1.1 200 OK\r\nContent-Length: 4\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\n",
            b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n4\r\nbody\r\n",
        ] {
            let result = exchange(response, use_tls, false, true, "GET", 4096);
            assert!(matches!(result.outcome, Err(HostIoError::Io { .. })));
        }
    }
}

#[test]
fn raw_successes_and_truncation_errors_replay_after_the_live_server_is_gone() {
    for response in [CHUNKED, TRUNCATED] {
        let recorded = exchange(response, true, false, true, "GET", 4096);
        let bytes = serde_json::to_vec(&recorded.entries).unwrap();
        let replay = InMemoryHostEffectJournal::replaying(serde_json::from_slice(&bytes).unwrap());
        replay.begin_execution().unwrap();
        let directory = tempfile::tempdir().unwrap();
        let provider = SandboxedHostIo::with_root(directory.path()).unwrap();
        // A mistaken live dispatch cannot reproduce the recording: the old
        // listener is gone and this fresh provider lacks its private CA.
        let outcome = match replay.replay_host_io(&recorded.request) {
            Some(outcome) => outcome,
            None => provider.perform(&recorded.request, &[HostIoCapability::NetworkSend]),
        };
        assert_eq!(outcome, recorded.outcome);
        assert_eq!(replay.finish_execution().unwrap(), recorded.entries);
    }
}

// Progress arrives more often than the configured timeout. A per-syscall
// timeout would accept the entire response; the shared deadline must not.
fn trickle<S: Read + Write>(stream: &mut S, http: bool, stop: &mpsc::Receiver<()>) -> usize {
    if http {
        let mut request = Vec::new();
        let mut buffer = [0_u8; 256];
        while !request.windows(4).any(|part| part == b"\r\n\r\n") {
            let count = stream.read(&mut buffer).expect("read test request");
            assert_ne!(count, 0);
            request.extend_from_slice(&buffer[..count]);
            assert!(request.len() <= 4096);
        }
        stream
            .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 64\r\n\r\n")
            .unwrap();
        stream.flush().unwrap();
    }
    let mut sent = 0;
    for byte in 0..64_u8 {
        if stream
            .write_all(&[byte])
            .and_then(|()| stream.flush())
            .is_err()
        {
            break;
        }
        sent += 1;
        match stop.recv_timeout(Duration::from_millis(100)) {
            Ok(()) | Err(mpsc::RecvTimeoutError::Disconnected) => break,
            Err(mpsc::RecvTimeoutError::Timeout) => {}
        }
    }
    sent
}

fn deadline_trickle_exchange(http: bool, use_tls: bool) {
    let directory = tempfile::tempdir().unwrap();
    let mut provider = SandboxedHostIo::with_root(directory.path())
        .unwrap()
        .with_network_timeout(Duration::from_secs(1))
        .unwrap();
    let tls_config = if use_tls {
        let (configured, config) = install_loopback_tls(provider);
        provider = configured;
        Some(config)
    } else {
        None
    };
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let endpoint = listener.local_addr().unwrap().to_string();
    let (stop, stopped) = mpsc::sync_channel(1);
    let server = std::thread::spawn(move || {
        let (mut stream, _) = listener.accept().unwrap();
        stream
            .set_read_timeout(Some(Duration::from_secs(5)))
            .unwrap();
        stream
            .set_write_timeout(Some(Duration::from_secs(5)))
            .unwrap();
        if let Some(config) = tls_config {
            let conn = rustls::ServerConnection::new(config).unwrap();
            let mut stream = rustls::StreamOwned::new(conn, stream);
            trickle(&mut stream, http, &stopped)
        } else {
            trickle(&mut stream, http, &stopped)
        }
    });
    let request = if http {
        HostIoRequest::NetworkRequest {
            endpoint,
            payload: b"GET / HTTP/1.1\r\nHost: loopback\r\n\r\n".to_vec(),
            max_len: 4096,
            use_tls,
        }
    } else {
        HostIoRequest::NetworkRecv {
            endpoint,
            max_len: 4096,
        }
    };
    let journal = InMemoryHostEffectJournal::recording();
    journal.begin_execution().unwrap();
    let reservation = journal.reserve_host_io(&request).unwrap();
    let outcome = provider.perform(&request, &[request.required_capability()]);
    let _ = stop.send(());
    let sent = server.join().unwrap();
    assert!(
        sent > 0 && sent < 64,
        "deadline must interrupt a genuinely progressing peer, sent={sent}"
    );
    assert!(
        matches!(outcome, Err(HostIoError::Io { .. })),
        "partial bytes are not successful output: {outcome:?}"
    );
    journal
        .complete_host_io(reservation, &request, &outcome)
        .unwrap();
    let entries = journal.finish_execution().unwrap();
    let replay = InMemoryHostEffectJournal::replaying(entries.clone());
    replay.begin_execution().unwrap();
    assert_eq!(replay.replay_host_io(&request), Some(outcome));
    assert_eq!(replay.finish_execution().unwrap(), entries);

    // The budget belongs to an individual effect, not to the provider's
    // lifetime. A fresh request through a clone gets its own deadline.
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let endpoint = listener.local_addr().unwrap().to_string();
    let next_server = std::thread::spawn(move || {
        let (mut stream, _) = listener.accept().unwrap();
        stream
            .set_read_timeout(Some(Duration::from_secs(5)))
            .unwrap();
        stream
            .set_write_timeout(Some(Duration::from_secs(5)))
            .unwrap();
        let (_sender, receiver) = mpsc::channel();
        serve(&mut stream, FIXED, false, &receiver);
    });
    let next = HostIoRequest::NetworkRequest {
        endpoint,
        payload: b"GET / HTTP/1.1\r\nHost: loopback\r\n\r\n".to_vec(),
        max_len: 4096,
        use_tls: false,
    };
    assert_eq!(
        provider
            .clone()
            .perform(&next, &[HostIoCapability::NetworkSend]),
        Ok(HostIoResponse::NetworkRequest {
            response: FIXED.to_vec()
        })
    );
    next_server.join().unwrap();
}

#[test]
fn tcp_response_progress_does_not_renew_the_deadline_and_timeout_replays() {
    deadline_trickle_exchange(true, false);
}

#[test]
fn tls_response_progress_does_not_renew_the_deadline_and_timeout_replays() {
    deadline_trickle_exchange(true, true);
}

#[test]
fn raw_network_receive_progress_does_not_renew_the_deadline() {
    deadline_trickle_exchange(false, false);
}

#[test]
fn tls_handshake_is_bounded_before_any_http_request_is_sent() {
    let directory = tempfile::tempdir().unwrap();
    let provider = SandboxedHostIo::with_root(directory.path())
        .unwrap()
        .with_network_timeout(Duration::from_secs(1))
        .unwrap();
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let endpoint = listener.local_addr().unwrap().to_string();
    let (release, receive) = mpsc::sync_channel(1);
    let server = std::thread::spawn(move || {
        let (mut stream, _) = listener.accept().unwrap();
        stream
            .set_read_timeout(Some(Duration::from_secs(5)))
            .unwrap();
        let mut hello = [0_u8; 1024];
        let count = stream.read(&mut hello).unwrap();
        assert!(count > 0, "real TLS client hello must cross the socket");
        // Deliberately never produce a ServerHello. The peer must time out
        // before our deadlock guard closes the connection.
        receive.recv_timeout(Duration::from_secs(5)).is_ok()
    });
    let request = HostIoRequest::NetworkRequest {
        endpoint,
        payload: b"GET / HTTP/1.1\r\nHost: loopback\r\n\r\n".to_vec(),
        max_len: 4096,
        use_tls: true,
    };
    let outcome = provider.perform(&request, &[HostIoCapability::NetworkSend]);
    let _ = release.send(());
    assert!(
        server.join().unwrap(),
        "handshake waited for server closure"
    );
    assert!(matches!(outcome, Err(HostIoError::Io { .. })));
}

#[test]
fn timeout_configuration_rejects_zero_and_overflow_without_bypassing_capabilities() {
    let directory = tempfile::tempdir().unwrap();
    let provider = SandboxedHostIo::with_root(directory.path()).unwrap();
    for timeout in [Duration::ZERO, Duration::MAX] {
        let error = provider.clone().with_network_timeout(timeout).unwrap_err();
        assert_eq!(error.kind(), std::io::ErrorKind::InvalidInput);
    }
    let provider = provider
        .with_network_timeout(Duration::from_secs(1))
        .unwrap();
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    listener.set_nonblocking(true).unwrap();
    let request = HostIoRequest::NetworkRequest {
        endpoint: listener.local_addr().unwrap().to_string(),
        payload: b"GET / HTTP/1.1\r\nHost: loopback\r\n\r\n".to_vec(),
        max_len: 4096,
        use_tls: false,
    };
    assert_eq!(
        provider.perform(&request, &[]),
        Err(HostIoError::CapabilityMissing {
            capability: HostIoCapability::NetworkSend,
        })
    );
    assert_eq!(
        listener.accept().unwrap_err().kind(),
        std::io::ErrorKind::WouldBlock
    );
}

struct NamedExchange {
    exchange: Exchange,
    observed: std::io::Result<(Vec<u8>, Option<String>)>,
}

fn named_exchange(
    listen: &str,
    hostname: Option<&str>,
    certificate: Option<&str>,
) -> NamedExchange {
    use std::time::Instant;
    let directory = tempfile::tempdir().unwrap();
    let mut provider = SandboxedHostIo::with_root(directory.path())
        .unwrap()
        .with_network_timeout(Duration::from_secs(3))
        .unwrap();
    let listener = TcpListener::bind(listen).expect("loopback family must be available");
    let address = listener.local_addr().unwrap();
    let endpoint = hostname.map_or_else(
        || address.to_string(),
        |host| format!("{host}:{}", address.port()),
    );
    let tls_config = certificate.map(|name| {
        let certified = rcgen::generate_simple_self_signed(vec![name.to_string()]).unwrap();
        provider = provider
            .clone()
            .with_extra_tls_roots_pem(certified.cert.pem().as_bytes())
            .unwrap();
        let key = rustls_pki_types::PrivateKeyDer::Pkcs8(certified.key_pair.serialize_der().into());
        Arc::new(
            rustls::ServerConfig::builder_with_provider(Arc::new(
                rustls::crypto::ring::default_provider(),
            ))
            .with_safe_default_protocol_versions()
            .unwrap()
            .with_no_client_auth()
            .with_single_cert(vec![certified.cert.der().clone()], key)
            .unwrap(),
        )
    });
    listener.set_nonblocking(true).unwrap();
    let (stop, stopped) = mpsc::sync_channel(1);
    let server = std::thread::spawn(move || -> std::io::Result<(Vec<u8>, Option<String>)> {
        let guard = Instant::now() + Duration::from_secs(5);
        let mut tcp = loop {
            match listener.accept() {
                Ok((tcp, _)) => break tcp,
                Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                    if stopped.try_recv().is_ok() || Instant::now() >= guard {
                        return Err(std::io::Error::new(
                            std::io::ErrorKind::TimedOut,
                            "no connection accepted",
                        ));
                    }
                    std::thread::sleep(Duration::from_millis(2));
                }
                Err(error) => return Err(error),
            }
        };
        tcp.set_nonblocking(false)?;
        tcp.set_read_timeout(Some(Duration::from_secs(5)))?;
        tcp.set_write_timeout(Some(Duration::from_secs(5)))?;
        fn reply<S: Read + Write>(stream: &mut S) -> std::io::Result<Vec<u8>> {
            let mut request = Vec::new();
            let mut byte = [0_u8; 1];
            while !request.ends_with(b"\r\n\r\n") {
                stream.read_exact(&mut byte)?;
                request.push(byte[0]);
                if request.len() > 4096 {
                    return Err(std::io::Error::other("oversized test request"));
                }
            }
            stream.write_all(FIXED)?;
            stream.flush()?;
            Ok(request)
        }
        if let Some(config) = tls_config {
            let connection =
                rustls::ServerConnection::new(config).map_err(std::io::Error::other)?;
            let mut tls = rustls::StreamOwned::new(connection, tcp);
            let request = reply(&mut tls)?;
            Ok((request, tls.conn.server_name().map(str::to_owned)))
        } else {
            Ok((reply(&mut tcp)?, None))
        }
    });
    let payload = format!("GET /family HTTP/1.1\r\nHost: {endpoint}\r\n\r\n").into_bytes();
    let request = HostIoRequest::NetworkRequest {
        endpoint,
        payload,
        max_len: 4096,
        use_tls: certificate.is_some(),
    };
    let journal = InMemoryHostEffectJournal::recording();
    journal.begin_execution().unwrap();
    let reservation = journal.reserve_host_io(&request).unwrap();
    let outcome = provider.perform(&request, &[HostIoCapability::NetworkSend]);
    let _ = stop.send(());
    let observed = server.join().expect("real named loopback server joins");
    journal
        .complete_host_io(reservation, &request, &outcome)
        .unwrap();
    NamedExchange {
        exchange: Exchange {
            outcome,
            request,
            entries: journal.finish_execution().unwrap(),
        },
        observed,
    }
}

#[test]
fn hostname_resolution_reaches_an_ipv4_only_server_over_tcp_and_tls() {
    for certificate in [None, Some("localhost")] {
        let named = named_exchange("127.0.0.1:0", Some("localhost"), certificate);
        assert_eq!(
            named.exchange.outcome,
            Ok(HostIoResponse::NetworkRequest {
                response: FIXED.to_vec()
            })
        );
        let (observed, sni) = named.observed.unwrap();
        let HostIoRequest::NetworkRequest { payload, .. } = &named.exchange.request else {
            unreachable!()
        };
        assert_eq!(&observed, payload);
        assert_eq!(sni.as_deref(), certificate);
    }
}

#[test]
fn ipv6_literal_tcp_and_tls_use_exact_ip_identity_without_sni() {
    for certificate in [None, Some("::1")] {
        let named = named_exchange("[::1]:0", None, certificate);
        assert_eq!(
            named.exchange.outcome,
            Ok(HostIoResponse::NetworkRequest {
                response: FIXED.to_vec()
            })
        );
        let (observed, sni) = named.observed.unwrap();
        let HostIoRequest::NetworkRequest { payload, .. } = &named.exchange.request else {
            unreachable!()
        };
        assert_eq!(&observed, payload);
        assert_eq!(sni, None);
    }
}

#[test]
fn hostname_tls_cannot_authenticate_only_the_resolved_address() {
    let named = named_exchange("127.0.0.1:0", Some("localhost"), Some("127.0.0.1"));
    assert!(matches!(
        named.exchange.outcome,
        Err(HostIoError::Io { .. })
    ));
    assert!(
        named.observed.is_err(),
        "a mismatched certificate must not receive the HTTP request"
    );
}

#[test]
fn ipv6_tls_rejects_a_trusted_certificate_for_another_ip() {
    let named = named_exchange("[::1]:0", None, Some("127.0.0.1"));
    assert!(matches!(
        named.exchange.outcome,
        Err(HostIoError::Io { .. })
    ));
    assert!(
        named.observed.is_err(),
        "IP certificate verification must not be disabled"
    );
}

#[test]
fn named_endpoint_replay_reuses_exact_outcome_after_the_server_is_gone() {
    let named = named_exchange("127.0.0.1:0", Some("localhost"), Some("localhost"));
    assert!(named.exchange.outcome.is_ok());
    let encoded = serde_json::to_vec(&named.exchange.entries).unwrap();
    let replay = InMemoryHostEffectJournal::replaying(serde_json::from_slice(&encoded).unwrap());
    replay.begin_execution().unwrap();
    assert_eq!(
        replay.replay_host_io(&named.exchange.request),
        Some(named.exchange.outcome)
    );
    assert_eq!(
        serde_json::to_vec(&replay.finish_execution().unwrap()).unwrap(),
        encoded
    );
}

#[derive(Debug, Default)]
struct ExecutionSignal(std::sync::atomic::AtomicBool);

impl frankenengine_extension_host::host_io::HostIoControl for ExecutionSignal {
    fn checkpoint(&self) -> Result<(), HostIoError> {
        if self.0.load(std::sync::atomic::Ordering::Acquire) {
            Err(HostIoError::Denied {
                reason: "execution stopped".into(),
            })
        } else {
            Ok(())
        }
    }
}

#[test]
fn operation_control_interrupts_real_tcp_tls_and_pinned_waits_without_poisoning_provider() {
    use std::sync::atomic::Ordering;
    for use_tls in [false, true] {
        for pinned in [false, true] {
            let directory = tempfile::tempdir().unwrap();
            let provider = SandboxedHostIo::with_root(directory.path())
                .unwrap()
                .with_network_timeout(Duration::from_secs(10))
                .unwrap();
            let (provider, tls_config) = install_loopback_tls(provider);
            let signal = Arc::new(ExecutionSignal::default());
            let sibling = provider.clone();
            let listener = TcpListener::bind("127.0.0.1:0").unwrap();
            let address = listener.local_addr().unwrap();
            let (ready, wait_ready) = mpsc::sync_channel(1);
            let (release, wait_release) = mpsc::sync_channel(1);
            let server = std::thread::spawn(move || {
                let mut tcp = accept_revocation_peer(&listener);
                if use_tls {
                    let connection = rustls::ServerConnection::new(tls_config).unwrap();
                    let mut tls = rustls::StreamOwned::new(connection, tcp);
                    hold_after_request(&mut tls, &ready, &wait_release)
                } else {
                    hold_after_request(&mut tcp, &ready, &wait_release)
                }
            });
            let request = HostIoRequest::NetworkRequest {
                endpoint: address.to_string(),
                payload: b"GET /once HTTP/1.1\r\nHost: loopback\r\n\r\n".to_vec(),
                max_len: 4096,
                use_tls,
            };
            let worker_request = request.clone();
            let worker_signal = signal.clone();
            let (done, wait_done) = mpsc::sync_channel(1);
            let worker = std::thread::spawn(move || {
                let result = if pinned {
                    provider.perform_pinned_network_candidates_controlled(
                        &worker_request,
                        &[HostIoCapability::NetworkSend],
                        &[address],
                        std::time::Instant::now() + Duration::from_secs(10),
                        worker_signal,
                    )
                } else {
                    provider.perform_controlled(
                        &worker_request,
                        &[HostIoCapability::NetworkSend],
                        worker_signal,
                    )
                };
                let _ = done.send(result);
            });
            let entered = wait_ready.recv_timeout(Duration::from_secs(5));
            signal.0.store(true, Ordering::Release);
            let result = wait_done.recv_timeout(Duration::from_secs(2));
            let _ = release.send(());
            worker.join().unwrap();
            let observed = server.join().unwrap();
            assert!(entered.is_ok());
            let HostIoRequest::NetworkRequest { payload, .. } = &request else {
                unreachable!()
            };
            assert_eq!(&observed, payload);
            let outcome =
                result.expect("execution cancellation cannot wait for the held-open peer");
            assert!(
                matches!(&outcome, Err(HostIoError::Denied { reason }) if reason == "HOST_IO_EXECUTION_CANCELLED")
            );
            assert!(!sibling.network_revocation().is_revoked());
            // A second real operation through the same provider proves that the
            // cancelled call did not leave a stale mutable control binding.
            let listener = TcpListener::bind("127.0.0.1:0").unwrap();
            let address = listener.local_addr().unwrap();
            let server = std::thread::spawn(move || {
                let mut tcp = accept_revocation_peer(&listener);
                tcp.write_all(b"sibling response").unwrap();
            });
            let sibling_request = HostIoRequest::NetworkRecv {
                endpoint: address.to_string(),
                max_len: 64,
            };
            assert_eq!(
                sibling.perform_controlled(
                    &sibling_request,
                    &[HostIoCapability::NetworkRecv],
                    Arc::new(ExecutionSignal::default())
                ),
                Ok(HostIoResponse::NetworkRecv {
                    bytes: b"sibling response".to_vec()
                })
            );
            server.join().unwrap();
            let journal = InMemoryHostEffectJournal::recording();
            journal.begin_execution().unwrap();
            let reservation = journal.reserve_host_io(&request).unwrap();
            journal
                .complete_host_io(reservation, &request, &outcome)
                .unwrap();
            let entries = journal.finish_execution().unwrap();
            let replay = InMemoryHostEffectJournal::replaying(entries.clone());
            replay.begin_execution().unwrap();
            assert_eq!(replay.replay_host_io(&request), Some(outcome));
            assert_eq!(replay.finish_execution().unwrap(), entries);
        }
    }
}

#[test]
fn cancelled_operation_denies_before_connect_and_cannot_weaken_provider_revocation() {
    use std::sync::atomic::Ordering;
    let directory = tempfile::tempdir().unwrap();
    let provider = SandboxedHostIo::with_root(directory.path()).unwrap();
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    listener.set_nonblocking(true).unwrap();
    let address = listener.local_addr().unwrap();
    let control = Arc::new(ExecutionSignal::default());
    control.0.store(true, Ordering::Release);
    let request = HostIoRequest::NetworkRecv {
        endpoint: address.to_string(),
        max_len: 8,
    };
    assert!(matches!(
        provider.perform_controlled(&request, &[HostIoCapability::NetworkRecv], control.clone()),
        Err(HostIoError::Denied { .. })
    ));
    assert!(
        provider
            .resolve_network_endpoint_controlled_until(
                &address.to_string(),
                std::time::Instant::now() + Duration::from_secs(5),
                control.clone()
            )
            .is_err()
    );
    assert!(!provider.network_revocation().is_revoked());
    control.0.store(false, Ordering::Release);
    provider.network_revocation().revoke();
    assert!(matches!(
        provider.perform_controlled(&request, &[HostIoCapability::NetworkRecv], control),
        Err(HostIoError::Denied { .. })
    ));
    assert_eq!(
        listener.accept().unwrap_err().kind(),
        std::io::ErrorKind::WouldBlock
    );
}
