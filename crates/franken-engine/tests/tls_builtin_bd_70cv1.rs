//! bd-70cv1: hermetic Node `tls` semantics over the engine loopback kernel.
//!
//! These tests intentionally do not claim cryptographic TLS records or OS
//! networking. They pin the finite API/verification/event surface exposed to
//! guest code while preserving the ambient-authority boundary.

use std::io::Write;
use std::process::Command;

use frankenengine_engine::HybridRouter;

const TLS_MATERIAL: &str = r#"
    const CERT = '-----BEGIN CERTIFICATE-----\nAQIDBA==\n-----END CERTIFICATE-----';
    const KEY = 'engine-contained-private-key-marker';
"#;

// Real self-signed certificate (CN=localhost) lifted from the
// `franken_node` `compat_corpus/tls/0008` fixture. The validity dates
// (2026-07-12..2026-07-13 UTC) are already in the past at the time of
// these tests, but the engine's hermetic TLS loopback does not enforce
// notAfter — it only stores the DER for `getPeerCertificate()` readers
// to surface. The 1-day window is the original fixture's choice; we
// pin the same cert so the engine output matches the same Node oracle
// the cross-repo fixture was designed for.
const LOCALHOST_CERT_PEM: &str = "-----BEGIN CERTIFICATE-----\n\
MIIDJzCCAg+gAwIBAgIUCnuirD955n02CW+OKsrgjTdSmiIwDQYJKoZIhvcNAQEL\n\
BQAwFDESMBAGA1UEAwwJbG9jYWxob3N0MCAXDTI2MDcxMjAyMjY1NloYDzIxMjYw\n\
NjE4MDIyNjU2WjAUMRIwEAYDVQQDDAlsb2NhbGhvc3QwggEiMA0GCSqGSIb3DQEB\n\
AQUAA4IBDwAwggEKAoIBAQC9AvES/Kj2lU2cugS2KT+kwJOCSpzUq/eYgFJohyF6\n\
OkrEH2rFuo0785vjR3Mz3qTmm0H47oaALaFNWqi9FjjSFrrSb069yMRdBhrIEwYf\n\
/Oc7Q7Ih3YIJ2DKV6QJujpadGFj6tgIcvhViMzFuwEQLc9NSLrX3pYbubxrlFW9z\n\
6slD3Hn5EraPa2cLUxVM/y9Gr6Rpg/HbviBujEVO7bAyFYKp1ba7beEKb5HYQbjr\n\
HKDJ2uil+IimvyX4e5LI4MWgeb/0CaOWSVNDUuIFqqflla4Vnr6cci8yMS26Kol/\n\
eimLlgAQFhFrzvnKnVgPYl8ETmsGZqH/CUVt+82dNSQ/AgMBAAGjbzBtMB0GA1Ud\n\
DgQWBBR8pQ3tgHxacZF0VKtEfKiWUkkBDTAfBgNVHSMEGDAWgBR8pQ3tgHxacZF0\n\
VKtEfKiWUkkBDTAPBgNVHRMBAf8EBTADAQH/MBoGA1UdEQQTMBGCCWxvY2FsaG9z\n\
dIcEfwAAATANBgkqhkiG9w0BAQsFAAOCAQEAiK2Yy+0HU2hqVOKpIF65cFrzi5bd\n\
ko87/RucGvT2/9zPSpyxDoHTHcVkzOnQiT6Q8AAwYb3NCQzOnjhwEhsfyL/Md24I\n\
YIZf1QQlMMb+pFtD6YhlASrNgu75M0CcSNofLLQlBLmI4Qk+hnqM2FFdZcwVLC8E\n\
XsrywCGXC0tS+KXEERlUofupBjVc8hptj34BKRDzVpKtsfMfTwrEvo+o83bxxn0Y\n\
MerW+K2JtfZ3cHMMuCiSJuEFL/maNgp4gXqB7BmWxozL25oGXaSK6o7Nsj6mzKPk\n\
MuBuJ7fs7RXPfUGm3EveNLiyi5aLTiwZ8ocZq6h4Bi1yJbnB5R+qHtl8QA==\n\
-----END CERTIFICATE-----";

const LOCALHOST_KEY_PEM: &str = "-----BEGIN PRIVATE KEY-----\n\
MIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQC9AvES/Kj2lU2c\n\
ugS2KT+kwJOCSpzUq/eYgFJohyF6OkrEH2rFuo0785vjR3Mz3qTmm0H47oaALaFN\n\
Wqi9FjjSFrrSb069yMRdBhrIEwYf/Oc7Q7Ih3YIJ2DKV6QJujpadGFj6tgIcvhV\n\
iMzFuwEQLc9NSLrX3pYbubxrlFW9z6slD3Hn5EraPa2cLUxVM/y9Gr6Rpg/HbviB\n\
ujEVO7bAyFYKp1ba7beEKb5HYQbjrHKDJ2uil+IimvyX4e5LI4MWgeb/0CaOWSVN\n\
DUuIFqqflla4Vnr6cci8yMS26Kol/eimLlgAQFhFrzvnKnVgPYl8ETmsGZqH/CUVt\n\
+82dNSQ/AgMBAAECggEAH2SOr82hLptrsZ0/zRWayX1mwpwr4jLRw9WEWnIfQFLQ\n\
OjTRohey/4MdoCks3C+dieO9mF/dnQp3IQbuwcEgHNzDmNH97Q2cd6rc5eArA0MZ\n\
EMHUo0VMJOBwvm9eBQjPwTXbCYETZry3hoDkM/XhF1ncfmjdtk0a1R1FBUmDImhR\n\
39nhf+x10rhh4pUY3piIeZZGXW7X/u3CtS31NkNCjP8S5okx5P+b53EptwedSBgP\n\
hZfRqq8Yz0L9DyHww+KPEzdrw04NtKfJhmNUHdjwPHQQE9M2rXax4/ni7WQ6uUFp\n\
GFG6nxIF3EtUrr5V18NdwbXtQRT40U/WsrXH3BYp6QKBgQD7PNFVatKRaoHNN6Sz\n\
v/8tFIsuZrm6B8NfEQ+G032IwYtuuiWz1cYgRxzN7zypB4WLSTTXTnU2yyZ6B4mD\n\
S/N6zYs/C/+XcXTKMp+FoA+Y1FuiDCKLWAR8w9ZkWaru5POsC3MxEOKV3N3ScxBV\n\
YKGBhoB5hGMr+prlp2zSf0OX8wKBgQDAmCi4kBYBdlQ+VyCHnHE5uHCFcitK9Dqv\n\
/IEiAfoYVaqbRYEy/PNMCfi7fG03+LmwW28rUW1dg7xRfF0koqSk7dNE/Ml3EPgL\n\
VKY5xfvP+y7K6qs/yWrdzp8cRgNIKNVQ/HWedY4Z+OOJdbmKegsT412AdCfewzLZ\n\
Km5G05PBhQKBgQDlVyo8UAwx5EjjPaUi1OQqkbNPw0RNdmK5OIi06gCRQyR2CoT6\n\
Oe3nbyLzNi1om04jzMrotF05jI7uHE1CRqXXdyRihCBobZBQN4/5WhiCyW9waKVs\n\
EAfgoKDn8BaihuuNJNKdeq1sYjc3sgO5/EDSTSagRuKEtfqKI6CqMrRQUwKBgAMS\n\
6qN3eUJwtwt/rH89mfkH3pPirJo3p7AjYZQ/X9R/mYd85oD/1IpEJnonlD6uc5hC\n\
/VU9qXcyoRDT4VCyX9paCWMyfayu0qarpTOK22gIZEjM0grklhYQNC3pWCgQrsbq\n\
IJ501d3IQSlyfZGePQsGN/nS4MgHaYpZyQTMX7FZAoGBAIvQ1I9x8F8cTSrA+RwL\n\
E5hh6HqImT9lbfpDnvEo+oB5Co26sgBsCI2BRE6/GWhEYFBblyHiJmmEoLkOJtpn\n\
0lBKrwmVzw5XYWuWsowj84qpsoPTQ8MoRCe02/+4SCRfEWzT2RG/THaQ1/d4XzV5\n\
Dc95hIOE29WCbZoLR99gbNx2\n\
-----END PRIVATE KEY-----";

const LOCALHOST_CERT_MATERIAL: &str = r#"
    const CERT = 'REAL_CERT_PLACEHOLDER';
    const KEY = 'REAL_KEY_PLACEHOLDER';
"#;

// Build the material with the real PEM substituted in. We assemble the
// raw string at runtime so the test source stays readable.
fn localhost_cert_material() -> String {
    LOCALHOST_CERT_MATERIAL
        .replace("REAL_CERT_PLACEHOLDER", LOCALHOST_CERT_PEM)
        .replace("REAL_KEY_PLACEHOLDER", LOCALHOST_KEY_PEM)
}

#[test]
fn tls_get_peer_certificate_subject_cn_matches_franken_node_fixture_0008() {
    // Mirror of `franken_node/tests/fixtures/compat_corpus/tls/0008_*`:
    // after handshake the client observes `subject.CN` from
    // `getPeerCertificate()`. The engine's bounded X.509 parser
    // (bd-il0d9) is the only place this metadata comes from.
    let material = localhost_cert_material();
    let source = format!(
        r#"
        {material}
        const tls = require('tls');
        const server = tls.createServer({{ cert: CERT, key: KEY }}, sock => {{ sock.end(); }});
        server.listen(0, '127.0.0.1', () => {{
          const c = tls.connect({{
            port: server.address().port,
            host: '127.0.0.1',
            rejectUnauthorized: false,
          }}, () => {{
            console.log('cn:' + c.getPeerCertificate().subject.CN);
            c.end();
          }});
          c.on('close', () => server.close());
        }});
        "#
    );
    assert_eq!(eval_console(&source), "cn:localhost");
}

#[test]
fn tls_get_peer_certificate_issuer_cn_matches_franken_node_fixture_0022() {
    // Mirror of `franken_node/tests/fixtures/compat_corpus/tls/0022_*`:
    // both `subject.CN` and `issuer.CN` come back, and for this
    // self-signed cert they are equal. Asserting both in one test
    // makes a regression in either field obvious.
    let material = localhost_cert_material();
    let source = format!(
        r#"
        {material}
        const tls = require('tls');
        const server = tls.createServer({{ cert: CERT, key: KEY }}, sock => {{ sock.end(); }});
        server.listen(0, '127.0.0.1', () => {{
          const c = tls.connect({{
            port: server.address().port,
            host: '127.0.0.1',
            rejectUnauthorized: false,
          }}, () => {{
            const p = c.getPeerCertificate();
            console.log('self-signed:' + (p.issuer.CN === p.subject.CN) + ' cn:' + p.subject.CN);
            c.end();
          }});
          c.on('close', () => server.close());
        }});
        "#
    );
    assert_eq!(eval_console(&source), "self-signed:true cn:localhost");
}

#[test]
fn tls_get_peer_certificate_validity_fields_match_franken_node_fixture_0023() {
    // Mirror of `franken_node/tests/fixtures/compat_corpus/tls/0023_*`:
    // `valid_from` and `valid_to` are returned as strings (the Node
    // fixture only checks `typeof`, which is always 'string' for our
    // parser's MMM DD HH:MM:SS YYYY GMT output).
    let material = localhost_cert_material();
    let source = format!(
        r#"
        {material}
        const tls = require('tls');
        const server = tls.createServer({{ cert: CERT, key: KEY }}, sock => {{ sock.end(); }});
        server.listen(0, '127.0.0.1', () => {{
          const c = tls.connect({{
            port: server.address().port,
            host: '127.0.0.1',
            rejectUnauthorized: false,
          }}, () => {{
            const p = c.getPeerCertificate();
            console.log('from:' + (typeof p.valid_from === 'string') + ' to:' + (typeof p.valid_to === 'string'));
            c.end();
          }});
          c.on('close', () => server.close());
        }});
        "#
    );
    assert_eq!(eval_console(&source), "from:true to:true");
}

#[test]
fn tls_get_peer_certificate_malformed_der_does_not_corrupt_raw_buffer() {
    // Adversarial: a server presenting only 4 bytes of placeholder DER
    // (the `TLS_MATERIAL` CERT constant) must still surface `raw` as a
    // Buffer; the bounded parser must return an `Err`, which the
    // interpreter then elides as "no metadata fields" rather than
    // dropping `raw` or surfacing garbage.
    let source = format!(
        r#"
        {TLS_MATERIAL}
        const tls = require('tls');
        const server = tls.createServer({{ cert: CERT, key: KEY }}, sock => {{ sock.end(); }});
        server.listen(0, '127.0.0.1', () => {{
          const c = tls.connect({{
            port: server.address().port,
            host: '127.0.0.1',
            rejectUnauthorized: false,
          }}, () => {{
            const p = c.getPeerCertificate();
            console.log('raw:' + Buffer.isBuffer(p.raw) + ' subject:' + (p.subject === undefined));
            c.end();
          }});
          c.on('close', () => server.close());
        }});
        "#
    );
    assert_eq!(eval_console(&source), "raw:true subject:true");
}

fn eval_console(source: &str) -> String {
    let mut engine = HybridRouter::default();
    let outcome = engine
        .eval(source)
        .unwrap_or_else(|error| panic!("eval failed for {source:?}: {error}"));
    outcome
        .console_output
        .iter()
        .map(|entry| entry.message.clone())
        .collect::<Vec<_>>()
        .join("\n")
}

fn eval_error(source: &str) -> String {
    let mut engine = HybridRouter::default();
    match engine.eval(source) {
        Ok(outcome) => panic!("expected eval error for {source:?}, got {outcome:?}"),
        Err(error) => error.to_string(),
    }
}

#[test]
fn static_tls_surface_is_deterministic_and_engine_contained() {
    let source = r#"
        const tls = require('node:tls');
        const roots = tls.rootCertificates;
        const ciphers = tls.getCiphers();
        const context = tls.createSecureContext({});
        console.log(Array.isArray(roots), roots[0].includes('BEGIN CERTIFICATE'));
        console.log(Array.isArray(ciphers), ciphers.length > 0, ciphers[0] === ciphers[0].toLowerCase());
        console.log(typeof context, tls.DEFAULT_MIN_VERSION);
    "#;
    assert_eq!(
        eval_console(source),
        "true true\ntrue true true\nobject TLSv1.2"
    );
}

#[test]
fn check_server_identity_returns_a_real_error_object_on_mismatch() {
    let source = r#"
        const tls = require('tls');
        const cert = { subject: { CN: 'localhost' }, subjectaltname: 'DNS:localhost' };
        const ok = tls.checkServerIdentity('localhost', cert);
        const bad = tls.checkServerIdentity('other.example', cert);
        const sanWins = tls.checkServerIdentity('localhost', {
          subject: { CN: 'localhost' },
          subjectaltname: 'DNS:other.example'
        });
        const dnsIp = tls.checkServerIdentity('127.0.0.1', {
          subject: { CN: '127.0.0.1' },
          subjectaltname: 'DNS:127.0.0.1'
        });
        const ipSan = tls.checkServerIdentity('127.0.0.1', {
          subject: { CN: 'wrong.example' },
          subjectaltname: 'IP Address:127.0.0.1'
        });
        console.log(ok === undefined, bad instanceof Error, bad.code);
        console.log(sanWins instanceof Error, sanWins.code);
        console.log(dnsIp instanceof Error, ipSan === undefined);
    "#;
    assert_eq!(
        eval_console(source),
        "true true ERR_TLS_CERT_ALTNAME_INVALID\n\
         true ERR_TLS_CERT_ALTNAME_INVALID\n\
         true true"
    );
}

#[test]
fn secure_events_gate_bidirectional_loopback_application_data() {
    let source = format!(
        r#"
        {TLS_MATERIAL}
        const tls = require('tls');
        const server = tls.createServer({{ cert: CERT, key: KEY }}, socket => {{
          socket.on('data', chunk => socket.end(String(chunk).toUpperCase()));
        }});
        server.on('secureConnection', socket => console.log('server:' + socket.encrypted));
        server.listen(0, '127.0.0.1', () => {{
          const client = tls.connect({{
            port: server.address().port,
            host: '127.0.0.1',
            servername: 'localhost',
            rejectUnauthorized: false
          }}, () => {{
            console.log('client:' + client.encrypted, 'authorized:' + client.authorized);
            client.write('quiet');
          }});
          let body = '';
          client.on('data', chunk => body += chunk);
          client.on('end', () => {{ console.log(body); server.close(); }});
        }});
        "#
    );
    assert_eq!(
        eval_console(&source),
        "server:true\nclient:true authorized:false\nQUIET"
    );
}

#[test]
fn negotiated_metadata_and_session_methods_are_tls_shaped() {
    let source = format!(
        r#"
        {TLS_MATERIAL}
        const tls = require('tls');
        const server = tls.createServer({{
          cert: CERT,
          key: KEY,
          ALPNProtocols: ['h2', 'http/1.1']
        }}, socket => {{ console.log('sni:' + socket.servername); socket.end(); }});
        server.listen(0, '127.0.0.1', () => {{
          const client = tls.connect({{
            port: server.address().port,
            host: '127.0.0.1',
            servername: 'localhost',
            ALPNProtocols: ['http/1.1'],
            rejectUnauthorized: false
          }}, () => {{
            console.log(client.getProtocol(), client.getCipher().version, client.alpnProtocol);
            console.log(client.isSessionReused(), client.getSession() === null);
            console.log(Buffer.isBuffer(client.getPeerCertificate(true).raw));
            client.end();
          }});
          client.on('close', () => server.close());
        }});
        "#
    );
    assert_eq!(
        eval_console(&source),
        "sni:localhost\nTLSv1.3 TLSv1.3 http/1.1\nfalse true\ntrue"
    );
}

#[test]
fn default_certificate_verification_fails_closed_before_secure_events() {
    let source = format!(
        r#"
        {TLS_MATERIAL}
        const tls = require('tls');
        const server = tls.createServer({{ cert: CERT, key: KEY }}, () => console.log('unexpected-server'));
        server.listen(0, '127.0.0.1', () => {{
          const client = tls.connect({{ port: server.address().port, host: '127.0.0.1' }});
          client.on('secureConnect', () => console.log('unexpected-client'));
          client.on('data', () => console.log('unexpected-data'));
          client.on('error', error => {{ console.log(error.code); server.close(); }});
        }});
        "#
    );
    assert_eq!(eval_console(&source), "DEPTH_ZERO_SELF_SIGNED_CERT");
}

#[test]
fn plain_net_clients_cannot_cross_the_tls_server_boundary() {
    let source = format!(
        r#"
        {TLS_MATERIAL}
        const tls = require('tls');
        const net = require('net');
        const server = tls.createServer({{ cert: CERT, key: KEY }}, () => console.log('unexpected-secure'));
        server.listen(0, '127.0.0.1', () => {{
          const client = net.connect({{ port: server.address().port, host: '127.0.0.1' }});
          client.on('connect', () => console.log('unexpected-plain-connect'));
          client.on('error', error => {{ console.log(error.code); server.close(); }});
        }});
        "#
    );
    assert_eq!(eval_console(&source), "ERR_SSL_HTTP_REQUEST");
}

#[test]
fn required_client_auth_fails_closed_without_a_trust_validator() {
    let source = format!(
        r#"
        {TLS_MATERIAL}
        const tls = require('tls');
        const server = tls.createServer({{
          cert: CERT,
          key: KEY,
          requestCert: true,
          rejectUnauthorized: true
        }}, () => console.log('unexpected-authorized-client'));
        server.listen(0, '127.0.0.1', () => {{
          const client = tls.connect({{
            port: server.address().port,
            host: '127.0.0.1',
            rejectUnauthorized: false
          }});
          client.on('secureConnect', () => console.log('unexpected-secure-connect'));
          client.on('error', error => {{ console.log(error.code); server.close(); }});
        }});
        "#
    );
    assert_eq!(eval_console(&source), "UNABLE_TO_VERIFY_LEAF_SIGNATURE");
}

#[test]
fn tls_socket_is_a_net_socket_without_materializing_either_module() {
    let source = format!(
        r#"
        {TLS_MATERIAL}
        const tls = require('tls');
        const net = require('net');
        const server = tls.createServer({{ cert: CERT, key: KEY }}, socket => socket.end());
        server.listen(0, '127.0.0.1', () => {{
          const client = tls.connect({{
            port: server.address().port,
            host: '127.0.0.1',
            rejectUnauthorized: false
          }}, () => {{ console.log(client instanceof net.Socket); client.end(); }});
          client.on('close', () => server.close());
        }});
        "#
    );
    assert_eq!(eval_console(&source), "true");
}

#[test]
fn forged_tls_type_tag_is_not_a_net_socket() {
    let source = r#"
        const net = require('net');
        const forged = { __type: 'TlsSocket' };
        console.log(forged instanceof net.Socket);
    "#;
    assert_eq!(eval_console(source), "false");
}

#[test]
fn pre_handshake_tls_metadata_is_unnegotiated() {
    let source = r#"
        const tls = require('tls');
        const client = tls.connect({
          port: 65535,
          host: '127.0.0.1',
          rejectUnauthorized: false
        });
        console.log(
          client.getProtocol() === undefined,
          client.getCipher() === undefined,
          client.getSession() === undefined,
          client.authorizationError === undefined
        );
        client.on('error', () => {});
    "#;
    assert_eq!(eval_console(source), "true true true true");
}

#[test]
fn server_observes_tls_client_error_when_handshake_authentication_fails() {
    let source = format!(
        r#"
        {TLS_MATERIAL}
        const tls = require('tls');
        const server = tls.createServer({{ cert: CERT, key: KEY }});
        let outbound;
        server.on('tlsClientError', (error, socket) => {{
          console.log('server:' + error.code, socket.encrypted, socket !== outbound, socket.destroyed);
          server.close();
        }});
        server.listen(0, '127.0.0.1', () => {{
          outbound = tls.connect({{
            port: server.address().port,
            host: '127.0.0.1'
          }});
          outbound.on('error', error => console.log('client:' + error.code));
        }});
        "#
    );
    assert_eq!(
        eval_console(&source),
        "server:DEPTH_ZERO_SELF_SIGNED_CERT true true true\n\
         client:DEPTH_ZERO_SELF_SIGNED_CERT"
    );
}

#[test]
fn supported_tls_alias_in_unshadowed_default_expression_executes() {
    let source = r#"
        const tls = require('tls');
        function hasCiphers(value = tls.getCiphers()) {
          return Array.isArray(value) && value.length > 0;
        }
        console.log(hasCiphers());
    "#;
    assert_eq!(eval_console(source), "true");
}

#[test]
fn tls_option_strings_are_bounded_before_guest_controlled_allocation() {
    let source = r#"
        const tls = require('tls');
        try {
          tls.createServer({ ALPNProtocols: { length: 9223372036854775807 } });
        } catch (error) {
          console.log(error.name);
        }
        try {
          tls.connect({
            port: 1,
            host: '127.0.0.1',
            servername: 'x'.repeat(254),
            rejectUnauthorized: false
          });
        } catch (error) {
          console.log(error.name);
        }
    "#;
    assert_eq!(eval_console(source), "RangeError\nRangeError");
}

#[test]
fn unsupported_tls_possession_remains_ambient_refused() {
    for source in [
        "const tls = require('tls'); console.log('unreachable');",
        "const tls = require('tls'); console.log(typeof tls.unknownExport);",
        "const name = 'tls'; const tls = require(name); console.log(tls.getCiphers());",
        "const tls = require('tls'); tls.getCiphers(); console.log(tls);",
        "const tls = require('tls'); tls.connect = () => null; tls.connect({ port: 1 });",
        "const tls = require('tls'); function f(tls) { return tls.getCiphers(); }",
        "const tls = require('tls'); console.log(tls.connect);",
        "const tls = require('tls'); tls = {}; tls.getCiphers();",
        "const tls = require('tls'); const { connect } = tls; tls.getCiphers();",
        "const tls = require('tls'); tls.getCiphers(); function f(value = tls) {}",
        "const tls = require('tls'); tls.getCiphers(); const { value = tls } = {};",
        "tls.getCiphers(); const tls = require('tls');",
        "f(); const tls = require('tls'); function f() { return tls.getCiphers(); }",
        "const ciphers = tls.getCiphers(), tls = require('tls');",
    ] {
        let error = eval_error(source);
        assert!(
            error.contains("ambient authority violation"),
            "unsupported TLS possession must fail closed, got: {error}"
        );
    }
}

#[test]
fn positional_connect_overloads_execute_with_expected_fidelity() {
    let source = format!(
        r#"
        {TLS_MATERIAL}
        const tls = require('tls');
        const server = tls.createServer({{ cert: CERT, key: KEY }}, socket => {{
          socket.on('data', chunk => socket.end('ECHO:' + chunk));
        }});
        server.listen(0, '127.0.0.1', () => {{
          const port = server.address().port;
          // Test overload: connect(port, host, options, callback)
          const client = tls.connect(port, '127.0.0.1', {{ rejectUnauthorized: false }}, () => {{
            client.write('pos-four');
          }});
          let body = '';
          client.on('data', chunk => body += chunk);
          client.on('end', () => {{
            console.log(body);
            // Test overload: connect(port, options, callback)
            const client2 = tls.connect(port, {{ rejectUnauthorized: false }}, () => {{
              client2.write('pos-three');
            }});
            let body2 = '';
            client2.on('data', chunk => body2 += chunk);
            client2.on('end', () => {{
              console.log(body2);
              server.close();
            }});
          }});
        }});
        "#
    );
    assert_eq!(eval_console(&source), "ECHO:pos-four\nECHO:pos-three");
}

#[test]
fn rfc6125_wildcard_san_matching_and_tld_rejection() {
    let source = r#"
        const tls = require('tls');
        const wildcardCert = {
          subject: { CN: 'sub.example.com' },
          subjectaltname: 'DNS:*.example.com, DNS:b*r.example.org'
        };
        const okSub = tls.checkServerIdentity('foo.example.com', wildcardCert);
        const okCase = tls.checkServerIdentity('BAR.EXAMPLE.COM', wildcardCert);
        const okPartial = tls.checkServerIdentity('bazr.example.org', wildcardCert);
        const badNested = tls.checkServerIdentity('nested.sub.example.com', wildcardCert);
        const badApex = tls.checkServerIdentity('example.com', wildcardCert);

        const tldWildcardCert = {
          subject: { CN: 'test' },
          subjectaltname: 'DNS:*.com, DNS:*'
        };
        const badTld = tls.checkServerIdentity('example.com', tldWildcardCert);
        const badSingle = tls.checkServerIdentity('localhost', tldWildcardCert);

        console.log(okSub === undefined, okCase === undefined, okPartial === undefined);
        console.log(badNested instanceof Error, badNested.code);
        console.log(badApex instanceof Error, badApex.code);
        console.log(badTld instanceof Error, badSingle instanceof Error);
    "#;
    assert_eq!(
        eval_console(source),
        "true true true\n\
         true ERR_TLS_CERT_ALTNAME_INVALID\n\
         true ERR_TLS_CERT_ALTNAME_INVALID\n\
         true true"
    );
}

#[test]
fn root_certificates_bundle_contains_valid_pem_and_parsed_der() {
    let source = r#"
        const tls = require('tls');
        const roots = tls.rootCertificates;
        console.log(Array.isArray(roots), roots.length >= 1);
        console.log(roots[0].startsWith('-----BEGIN CERTIFICATE-----\n'));
        console.log(roots[0].endsWith('\n-----END CERTIFICATE-----'));
    "#;
    assert_eq!(eval_console(source), "true true\ntrue\ntrue");
}

/// Prefer a real Node binary over bun's `node` shim, which rejects `--version`.
fn live_node_binary() -> Option<String> {
    for candidate in ["node", "nodejs"] {
        let output = match Command::new(candidate).arg("--version").output() {
            Ok(output) => output,
            Err(_) => continue,
        };
        if !output.status.success() {
            continue;
        }
        let version = String::from_utf8_lossy(&output.stdout);
        if version.trim_start().starts_with('v') {
            return Some(candidate.to_string());
        }
    }
    None
}

fn live_node_eval_js(script: &str) -> Option<String> {
    let node = live_node_binary()?;
    let child = Command::new(&node)
        .arg("-e")
        .arg(script)
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .ok()?;
    let output = child.wait_with_output().ok()?;
    if !output.status.success() {
        return None;
    }
    Some(String::from_utf8_lossy(&output.stdout).trim().to_string())
}

#[test]
fn live_node_check_server_identity_oracle_matches_engine() {
    const IDENTITY_SCRIPT: &str = r#"
        const tls = require('tls');
        function report(host, cert) {
          const result = tls.checkServerIdentity(host, cert);
          const code = result === undefined ? 'ok' : ('' + result.code);
          console.log(host + '|' + code);
        }
        const wildcard = { subject: { CN: 'sub.example.com' }, subjectaltname: 'DNS:*.example.com, DNS:b*r.example.org' };
        const tld = { subject: { CN: 'test' }, subjectaltname: 'DNS:*.com, DNS:*' };
        const idn = { subject: { CN: 'x' }, subjectaltname: 'DNS:xn--*.example.com' };
        report('foo.example.com', wildcard);
        report('BAR.EXAMPLE.COM', wildcard);
        report('bazr.example.org', wildcard);
        report('nested.sub.example.com', wildcard);
        report('example.com', wildcard);
        report('example.com', tld);
        report('localhost', tld);
        report('foo.example.com', idn);
    "#;

    let Some(node_stdout) = live_node_eval_js(IDENTITY_SCRIPT) else {
        eprintln!(
            "skipping live-Node oracle: no Node binary that accepts --version was found on PATH"
        );
        return;
    };
    let engine_stdout = eval_console(IDENTITY_SCRIPT);
    assert_eq!(
        node_stdout, engine_stdout,
        "engine checkServerIdentity must match live Node for RFC 6125 vectors"
    );
}

#[test]
fn live_node_parses_engine_isrg_root_pem() {
    let Some(node) = live_node_binary() else {
        eprintln!(
            "skipping live-Node PEM oracle: no Node binary that accepts --version was found on PATH"
        );
        return;
    };

    let pem = eval_console(
        r#"
        const tls = require('tls');
        console.log(tls.rootCertificates[0]);
        "#,
    );
    assert!(
        pem.contains("BEGIN CERTIFICATE"),
        "engine root bundle should be PEM, got: {pem:?}"
    );

    let mut child = Command::new(&node)
        .arg("-e")
        .arg(
            r#"
            const { X509Certificate } = require('crypto');
            const chunks = [];
            process.stdin.on('data', chunk => chunks.push(chunk));
            process.stdin.on('end', () => {
              const pem = Buffer.concat(chunks).toString('utf8');
              const cert = new X509Certificate(pem);
              process.stdout.write(JSON.stringify({
                subject: cert.subject,
                issuer: cert.issuer,
                validFrom: cert.validFrom,
                validTo: cert.validTo
              }));
            });
            "#,
        )
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .expect("live Node X509 parse should spawn");
    {
        let mut stdin = child.stdin.take().expect("live Node stdin");
        stdin
            .write_all(pem.as_bytes())
            .expect("live Node stdin write");
    }
    let output = child
        .wait_with_output()
        .expect("live Node X509 parse should finish");
    assert!(
        output.status.success(),
        "Node rejected engine ISRG Root X1 PEM: stdout={} stderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    let parsed = String::from_utf8_lossy(&output.stdout);
    assert!(
        parsed.contains("ISRG Root X1"),
        "parsed subject/issuer should name ISRG Root X1, got: {parsed}"
    );
}
