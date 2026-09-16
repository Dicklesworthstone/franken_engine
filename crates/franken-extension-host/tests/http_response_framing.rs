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
        let certified = rcgen::generate_simple_self_signed(vec!["127.0.0.1".to_string()])
            .expect("generate loopback TLS certificate");
        provider = provider
            .with_extra_tls_roots_pem(certified.cert.pem().as_bytes())
            .expect("install explicit test trust anchor");
        let key = rustls_pki_types::PrivateKeyDer::Pkcs8(certified.key_pair.serialize_der().into());
        let crypto = Arc::new(rustls::crypto::ring::default_provider());
        Some(Arc::new(
            rustls::ServerConfig::builder_with_provider(crypto)
                .with_safe_default_protocol_versions()
                .expect("TLS versions")
                .with_no_client_auth()
                .with_single_cert(vec![certified.cert.der().clone()], key)
                .expect("TLS server certificate"),
        ))
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
