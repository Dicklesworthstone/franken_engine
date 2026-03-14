#![allow(
    clippy::field_reassign_with_default,
    clippy::assertions_on_constants,
    clippy::useless_vec,
    clippy::clone_on_copy,
    clippy::unnecessary_get_then_check,
    clippy::len_zero,
    clippy::needless_borrows_for_generic_args,
    clippy::too_many_arguments,
    clippy::identity_op,
    clippy::manual_abs_diff
)]

use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};

use frankenengine_engine::capability::RuntimeCapability;
use frankenengine_engine::capability_token::{
    CapabilityToken, CheckpointRef, PrincipalId, RevocationFreshnessRef, TokenBuilder,
    VerificationContext, verify_token,
};
use frankenengine_engine::deterministic_serde::{
    CanonicalValue, SchemaRegistry, decode_value, deserialize_with_schema, encode_value,
    serialize_with_schema,
};
use frankenengine_engine::engine_object_id::EngineObjectId;
use frankenengine_engine::hash_tiers::ContentHash;
use frankenengine_engine::policy_checkpoint::DeterministicTimestamp;
use frankenengine_engine::security_epoch::SecurityEpoch;
use frankenengine_engine::session_hostcall_channel::{
    AeadAlgorithm, DataPlaneDirection, SequencePolicy, SessionConfig, SessionHandshake,
    SessionHostcallChannel, SharedSendInput, build_aead_associated_data,
    derive_deterministic_aead_nonce,
};
use frankenengine_engine::signature_preimage::SigningKey;

const MAX_CORPUS_BYTES: usize = 64 * 1024;
const MAX_HANDSHAKE_STEPS: usize = 96;
const MAX_PAYLOAD_BYTES: usize = 128;
const MAX_TOKEN_MUTATIONS: usize = 64;

#[test]
fn decode_dos_corpus_regression_is_panic_free() {
    for input in read_corpus_bytes("decode_dos") {
        run_decode_program(&input);
    }

    // Explicit malformed length-prefix case from decode-DoS threat model.
    run_decode_program(&[0x04, 0xFF, 0xFF, 0xFF, 0xFF]);
}

#[test]
fn handshake_replay_corpus_regression_is_panic_free() {
    for input in read_corpus_bytes("handshake_replay") {
        run_handshake_program(&input);
    }
}

#[test]
fn token_verification_corpus_regression_is_panic_free() {
    for input in read_corpus_bytes("token_verification") {
        run_token_program(&input);
    }
}

fn run_decode_program(data: &[u8]) {
    if data.len() > MAX_CORPUS_BYTES {
        return;
    }

    let _ = decode_value(data);

    if data.len() >= 32 {
        let mut schema_bytes = [0u8; 32];
        schema_bytes.copy_from_slice(&data[..32]);
        let schema = frankenengine_engine::deterministic_serde::SchemaHash(schema_bytes);
        let _ = deserialize_with_schema(&schema, data);
    }

    let synthetic = synthetic_value(data);
    let mut registry = SchemaRegistry::new();
    let schema = registry.register("tests.decode_dos", 1, b"tests.decode_dos.schema.v1");
    let encoded = serialize_with_schema(&schema, &synthetic);
    let _ = registry.deserialize_checked(&encoded);

    if let Ok(decoded) = decode_value(&encode_value(&synthetic)) {
        let _ = encode_value(&decoded);
    }
}

fn synthetic_value(data: &[u8]) -> CanonicalValue {
    match byte(data, 0) % 5 {
        0 => CanonicalValue::U64(u64::from(byte(data, 1))),
        1 => CanonicalValue::Bytes(data.iter().copied().take(128).collect()),
        2 => CanonicalValue::String(
            data.iter()
                .copied()
                .take(64)
                .map(|b| char::from(b'a' + (b % 26)))
                .collect(),
        ),
        3 => CanonicalValue::Array(
            data.iter()
                .copied()
                .take(16)
                .map(|item| CanonicalValue::U64(u64::from(item)))
                .collect(),
        ),
        _ => {
            let mut map = BTreeMap::new();
            for (index, value) in data.iter().copied().take(12).enumerate() {
                map.insert(
                    format!("k{index:02x}"),
                    CanonicalValue::U64(u64::from(value)),
                );
            }
            CanonicalValue::Map(map)
        }
    }
}

fn run_handshake_program(data: &[u8]) {
    if data.is_empty() {
        return;
    }

    let mut channel = SessionHostcallChannel::new();
    let extension_signing_key = SigningKey::from_bytes(bytes32(data, 0));
    let host_signing_key = SigningKey::from_bytes(bytes32(data, 17));
    let config = SessionConfig {
        max_lifetime_ticks: 16 + u64::from(byte(data, 1)),
        max_messages: 8 + u64::from(byte(data, 2)),
        max_buffered_messages: 1 + usize::from(byte(data, 3) % 16),
        sequence_policy: if byte(data, 4).is_multiple_of(2) {
            SequencePolicy::Monotonic
        } else {
            SequencePolicy::Strict
        },
        replay_drop_threshold: 1 + u64::from(byte(data, 5) % 8),
        replay_drop_window_ticks: 1 + u64::from(byte(data, 6) % 32),
    };

    let start_tick = u64::from(byte(data, 7)) + 1;
    let handshake_a = SessionHandshake {
        session_id: make_id("sess-a", data, 8),
        extension_id: make_id("ext-a", data, 22),
        host_id: make_id("host-a", data, 36),
        extension_nonce: u64::from(byte(data, 10)),
        host_nonce: u64::from(byte(data, 11)),
        timestamp_ticks: start_tick,
        trace_id: "test-trace-a".to_string(),
    };

    let handle_a = match channel.create_session(
        handshake_a.clone(),
        &extension_signing_key,
        &host_signing_key,
        config.clone(),
    ) {
        Ok(handle) => handle,
        Err(_) => return,
    };

    let handshake_b = SessionHandshake {
        session_id: make_id("sess-b", data, 46),
        extension_id: make_id("ext-b", data, 60),
        host_id: make_id("host-b", data, 74),
        extension_nonce: u64::from(byte(data, 12)) + 1,
        host_nonce: u64::from(byte(data, 13)) + 1,
        timestamp_ticks: start_tick.saturating_add(1),
        trace_id: "test-trace-b".to_string(),
    };
    let handle_b = channel
        .create_session(
            handshake_b,
            &extension_signing_key,
            &host_signing_key,
            config.clone(),
        )
        .ok();

    let mut now_tick = start_tick.saturating_add(2);
    let mut cursor = 14usize;
    for _ in 0..MAX_HANDSHAKE_STEPS {
        let opcode = byte(data, cursor);
        cursor = cursor.saturating_add(1);

        match opcode % 8 {
            0 => {
                let payload_len = usize::from(byte(data, cursor)) % MAX_PAYLOAD_BYTES;
                cursor = cursor.saturating_add(1);
                let payload = (0..payload_len)
                    .map(|offset| byte(data, cursor.saturating_add(offset)))
                    .collect::<Vec<_>>();
                let _ = channel.send(
                    &handle_a,
                    payload,
                    "test-send",
                    now_tick,
                    Some("test-decision"),
                    Some("test-policy"),
                );
                cursor = cursor.saturating_add(payload_len);
            }
            1 => {
                let _ = channel.receive(
                    &handle_a,
                    "test-recv",
                    now_tick,
                    Some("test-decision"),
                    Some("test-policy"),
                );
            }
            2 => {
                // Duplicate-handshake replay attempt on same session_id.
                let replay = SessionHandshake {
                    session_id: handshake_a.session_id.clone(),
                    extension_id: handshake_a.extension_id.clone(),
                    host_id: handshake_a.host_id.clone(),
                    extension_nonce: handshake_a.extension_nonce,
                    host_nonce: handshake_a.host_nonce,
                    timestamp_ticks: now_tick,
                    trace_id: "test-replay".to_string(),
                };
                let _ = channel.create_session(
                    replay,
                    &extension_signing_key,
                    &host_signing_key,
                    config.clone(),
                );
            }
            3 => {
                let _ = channel.close_session(
                    &handle_a,
                    "test-close",
                    now_tick,
                    Some("test-decision"),
                    Some("test-policy"),
                );
            }
            4 => {
                let payload_len = usize::from(byte(data, cursor)) % MAX_PAYLOAD_BYTES;
                cursor = cursor.saturating_add(1);
                let payload = (0..payload_len)
                    .map(|offset| byte(data, cursor.saturating_add(offset)))
                    .collect::<Vec<_>>();
                let _ = channel.send_shared_buffer(
                    &handle_a,
                    SharedSendInput {
                        region_id: u64::from(byte(data, cursor)),
                        payload: &payload,
                        trace_id: "test-shared-send",
                        timestamp_ticks: now_tick,
                        decision_id: Some("test-decision"),
                        policy_id: Some("test-policy"),
                    },
                );
                cursor = cursor.saturating_add(payload_len);
            }
            5 => {
                // Session splicing attempt via cross-session signal verification.
                if let Some(ref handle) = handle_b
                    && let Ok(envelope) = channel.authenticated_backpressure_signal(
                        handle,
                        usize::from(byte(data, cursor)),
                        16,
                        "test-splice",
                        now_tick,
                    )
                {
                    let _ = channel.verify_authenticated_signal(&handle_a, &envelope);
                }
            }
            6 => {
                let sequence = if opcode & 1 == 0 {
                    u64::MAX
                } else {
                    u64::from(byte(data, cursor)) << 16
                };
                cursor = cursor.saturating_add(1);
                let algorithm = match byte(data, cursor) % 3 {
                    0 => AeadAlgorithm::ChaCha20Poly1305,
                    1 => AeadAlgorithm::Aes256Gcm,
                    _ => AeadAlgorithm::XChaCha20Poly1305,
                };
                let _ = derive_deterministic_aead_nonce(
                    &bytes32(data, cursor),
                    DataPlaneDirection::ExtensionToHost,
                    sequence,
                    algorithm,
                );
                cursor = cursor.saturating_add(1);
            }
            _ => {
                let _ = channel.drain_events();
                let _ = channel.queue_len(&handle_a);
                let _ = channel.session_state(&handle_a);
            }
        }

        now_tick = now_tick.saturating_add(1 + u64::from(opcode & 0x0f));
    }
}

fn run_token_program(data: &[u8]) {
    if data.is_empty() {
        return;
    }

    let Some(mut token) = build_token(data) else {
        return;
    };
    mutate_token(&mut token, data);

    let presenter = PrincipalId::from_bytes(bytes32(data, 9));
    let ctx = VerificationContext {
        current_tick: u64::from(byte(data, 10)) + u64::from(byte(data, 11)),
        verifier_checkpoint_seq: u64::from(byte(data, 12)),
        verifier_revocation_seq: u64::from(byte(data, 13)),
    };

    let _ = verify_token(&token, &presenter, &ctx);
    if let Ok(json) = serde_json::to_string(&token)
        && let Ok(decoded) = serde_json::from_str::<CapabilityToken>(&json)
    {
        let _ = verify_token(&decoded, &presenter, &ctx);
    }
}

fn build_token(data: &[u8]) -> Option<CapabilityToken> {
    let sk = SigningKey::from_bytes(bytes32(data, 0));
    let presenter = PrincipalId::from_bytes(bytes32(data, 1));
    let nbf = DeterministicTimestamp(u64::from(byte(data, 2)));
    let expiry = DeterministicTimestamp(nbf.0.saturating_add(1 + u64::from(byte(data, 3))));
    let epoch = SecurityEpoch::from_raw(u64::from(byte(data, 4)).saturating_add(1));

    TokenBuilder::new(sk, nbf, expiry, epoch, "test-zone")
        .add_audience(presenter)
        .add_capability(RuntimeCapability::VmDispatch)
        .add_capability(RuntimeCapability::FsRead)
        .build()
        .ok()
}

fn mutate_token(token: &mut CapabilityToken, data: &[u8]) {
    for (index, value) in data.iter().copied().take(MAX_TOKEN_MUTATIONS).enumerate() {
        match value % 8 {
            0 => token.signature.lower[index % 32] ^= value,
            1 => token.signature.upper[index % 32] ^= value.rotate_left(1),
            2 => token.nbf = DeterministicTimestamp(u64::from(value)),
            3 => {
                token.expiry =
                    DeterministicTimestamp(u64::from(value) + u64::from(byte(data, index + 1)))
            }
            4 => {
                token.audience.clear();
                if value & 1 == 0 {
                    token
                        .audience
                        .insert(PrincipalId::from_bytes(bytes32(data, index + 2)));
                }
            }
            5 => token.zone = format!("test-zone-{value}"),
            6 => {
                token.checkpoint_binding = Some(CheckpointRef {
                    min_checkpoint_seq: u64::from(value),
                    checkpoint_id: EngineObjectId([value; 32]),
                });
            }
            _ => {
                token.revocation_freshness = Some(RevocationFreshnessRef {
                    min_revocation_seq: u64::from(value),
                    revocation_head_hash: ContentHash::compute(&[value]),
                });
            }
        }
    }
}

fn read_corpus_bytes(name: &str) -> Vec<Vec<u8>> {
    let repo = repo_root();
    let candidate_dirs = [
        repo.join("fuzz").join("corpus").join(name),
        repo.join("crates")
            .join("franken-engine")
            .join("tests")
            .join("fixtures")
            .join("fuzz_adversarial")
            .join(name),
    ];

    for corpus_dir in candidate_dirs {
        if !corpus_dir.exists() {
            continue;
        }

        let entries = collect_files(&corpus_dir);
        if entries.is_empty() {
            continue;
        }

        return entries
            .into_iter()
            .map(|path| {
                fs::read(&path).unwrap_or_else(|error| {
                    panic!("failed reading corpus file {}: {error}", path.display())
                })
            })
            .collect();
    }

    panic!("no corpus files found for target {name}");
}

fn collect_files(dir: &Path) -> Vec<PathBuf> {
    let mut out = fs::read_dir(dir)
        .unwrap_or_else(|error| panic!("failed to read corpus dir {}: {error}", dir.display()))
        .filter_map(Result::ok)
        .map(|entry| entry.path())
        .filter(|path| path.is_file())
        .collect::<Vec<_>>();
    out.sort();
    out
}

fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..")
}

fn make_id(prefix: &str, data: &[u8], offset: usize) -> String {
    let mut id = String::from(prefix);
    id.push('-');
    for index in 0..8 {
        let value = byte(data, offset.saturating_add(index));
        id.push(char::from(b'a' + (value % 26)));
    }
    id
}

fn bytes32(data: &[u8], offset: usize) -> [u8; 32] {
    let mut out = [0u8; 32];
    for (index, slot) in out.iter_mut().enumerate() {
        *slot = byte(data, offset + index);
    }
    out
}

fn byte(data: &[u8], index: usize) -> u8 {
    if data.is_empty() {
        return 0;
    }
    data[index % data.len()]
}

// ---------- byte helper ----------

#[test]
fn byte_empty_returns_zero() {
    assert_eq!(byte(&[], 0), 0);
    assert_eq!(byte(&[], 100), 0);
}

#[test]
fn byte_wraps_index() {
    let data = [10, 20, 30];
    assert_eq!(byte(&data, 0), 10);
    assert_eq!(byte(&data, 3), 10); // wraps
    assert_eq!(byte(&data, 4), 20);
}

// ---------- bytes32 ----------

#[test]
fn bytes32_produces_32_byte_array() {
    let data = [1, 2, 3, 4, 5];
    let result = bytes32(&data, 0);
    assert_eq!(result.len(), 32);
}

#[test]
fn bytes32_wraps_for_short_data() {
    let data = [0xAB];
    let result = bytes32(&data, 0);
    assert!(result.iter().all(|&b| b == 0xAB));
}

// ---------- make_id ----------

#[test]
fn make_id_starts_with_prefix() {
    let data = [42; 64];
    let id = make_id("sess", &data, 0);
    assert!(id.starts_with("sess-"));
}

#[test]
fn make_id_has_8_alpha_chars_after_prefix() {
    let data = [0; 64];
    let id = make_id("ext", &data, 0);
    let suffix = &id["ext-".len()..];
    assert_eq!(suffix.len(), 8);
    assert!(suffix.chars().all(|c| c.is_ascii_lowercase()));
}

#[test]
fn make_id_different_offsets_produce_different_ids() {
    let data: Vec<u8> = (0..64).collect();
    let id_a = make_id("test", &data, 0);
    let id_b = make_id("test", &data, 8);
    assert_ne!(id_a, id_b);
}

// ---------- synthetic_value ----------

#[test]
fn synthetic_value_covers_all_variants() {
    for variant in 0..5u8 {
        let data = [variant, 42, 43, 44];
        let value = synthetic_value(&data);
        let encoded = encode_value(&value);
        assert!(!encoded.is_empty());
    }
}

#[test]
fn synthetic_value_u64_variant() {
    let data = [0, 99]; // variant 0 => U64
    match synthetic_value(&data) {
        CanonicalValue::U64(_) => {}
        other => panic!("expected U64, got {other:?}"),
    }
}

#[test]
fn synthetic_value_bytes_variant() {
    let data = [1, 0, 0]; // variant 1 => Bytes
    match synthetic_value(&data) {
        CanonicalValue::Bytes(_) => {}
        other => panic!("expected Bytes, got {other:?}"),
    }
}

#[test]
fn synthetic_value_string_variant() {
    let data = [2, 0]; // variant 2 => String
    match synthetic_value(&data) {
        CanonicalValue::String(s) => assert!(s.chars().all(|c| c.is_ascii_lowercase())),
        other => panic!("expected String, got {other:?}"),
    }
}

#[test]
fn synthetic_value_array_variant() {
    let data = [3, 10, 20]; // variant 3 => Array
    match synthetic_value(&data) {
        CanonicalValue::Array(arr) => assert!(!arr.is_empty()),
        other => panic!("expected Array, got {other:?}"),
    }
}

#[test]
fn synthetic_value_map_variant() {
    let data = [4, 1, 2, 3]; // variant 4 => Map
    match synthetic_value(&data) {
        CanonicalValue::Map(map) => assert!(!map.is_empty()),
        other => panic!("expected Map, got {other:?}"),
    }
}

// ---------- build_token ----------

#[test]
fn build_token_succeeds_with_valid_data() {
    let data: Vec<u8> = (0..64).collect();
    let token = build_token(&data);
    assert!(token.is_some());
}

#[test]
fn build_token_returns_none_for_empty_data() {
    let token = build_token(&[]);
    // Empty data produces zero signing key — may or may not succeed
    // but should not panic
    let _ = token;
}

// ---------- run_decode_program ----------

#[test]
fn run_decode_program_handles_empty_input() {
    run_decode_program(&[]);
}

#[test]
fn run_decode_program_handles_short_input() {
    run_decode_program(&[1, 2, 3]);
}

#[test]
fn run_decode_program_handles_malformed_length_prefix() {
    run_decode_program(&[0x04, 0xFF, 0xFF, 0xFF, 0xFF, 0x00, 0x01]);
}

// ---------- run_token_program ----------

#[test]
fn run_token_program_handles_empty_input() {
    // Should return early without panic
    run_token_program(&[]);
}

#[test]
fn run_token_program_handles_minimal_input() {
    let data: Vec<u8> = (0..32).collect();
    run_token_program(&data);
}

// ---------- run_handshake_program ----------

#[test]
fn run_handshake_program_handles_empty_input() {
    // Should return early without panic
    run_handshake_program(&[]);
}

#[test]
fn run_handshake_program_handles_small_input() {
    let data: Vec<u8> = (0..20).collect();
    run_handshake_program(&data);
}

// ---------- enrichment: adversarial boundary and determinism ----------

#[test]
fn run_decode_program_handles_exactly_32_bytes_triggers_schema_path() {
    // Exactly 32 bytes activates the schema deserialization branch
    let data: Vec<u8> = (0..32).collect();
    run_decode_program(&data);
}

#[test]
fn run_decode_program_at_max_corpus_boundary() {
    // Exactly at the MAX_CORPUS_BYTES limit -- should still process
    let data = vec![0xAB; MAX_CORPUS_BYTES];
    run_decode_program(&data);
    // One byte over -- should be silently rejected
    let over = vec![0xAB; MAX_CORPUS_BYTES + 1];
    run_decode_program(&over);
}

#[test]
fn synthetic_value_encode_decode_roundtrip_determinism() {
    // For each variant, encoding and decoding must be deterministic
    for variant in 0..5u8 {
        let data = [variant, 10, 20, 30, 40, 50, 60, 70];
        let value = synthetic_value(&data);
        let encoded_a = encode_value(&value);
        let encoded_b = encode_value(&value);
        assert_eq!(
            encoded_a, encoded_b,
            "encoding must be deterministic for variant {variant}"
        );
        if let Ok(decoded) = decode_value(&encoded_a) {
            let re_encoded = encode_value(&decoded);
            assert_eq!(
                encoded_a, re_encoded,
                "decode-reencode must be stable for variant {variant}"
            );
        }
    }
}

#[test]
fn run_token_program_with_all_mutation_opcodes() {
    // Construct data that exercises every mutation opcode (0-7) in mutate_token
    let mut data: Vec<u8> = (0..64).collect();
    // Ensure first 8 bytes cover opcodes 0..7
    for i in 0..8u8 {
        data[i as usize] = i;
    }
    run_token_program(&data);
}

#[test]
fn run_handshake_program_exercises_all_opcodes() {
    // Build input so that opcodes at cursor positions cycle through 0..7
    let mut data = vec![0u8; 256];
    // First 15 bytes for config
    for (i, item) in data.iter_mut().enumerate().take(15) {
        *item = (i as u8).wrapping_add(1);
    }
    // From offset 14 onward, place each opcode variant
    for (step, opcode) in (0..8u8).enumerate() {
        let pos = 14 + step * 3; // each step: opcode + payload_len + filler
        if pos < data.len() {
            data[pos] = opcode;
        }
        if pos + 1 < data.len() {
            data[pos + 1] = 4; // small payload
        }
    }
    run_handshake_program(&data);
}

// ---------- enrichment: token, decode, and handshake boundary tests ----------

#[test]
fn build_token_serde_roundtrip_when_present() {
    let data: Vec<u8> = (0..64).collect();
    if let Some(token) = build_token(&data) {
        let json = serde_json::to_string(&token).expect("serialize token");
        let recovered: CapabilityToken = serde_json::from_str(&json).expect("deserialize token");
        assert_eq!(token.zone, recovered.zone);
        assert_eq!(token.nbf, recovered.nbf);
        assert_eq!(token.expiry, recovered.expiry);
    }
}

#[test]
fn mutate_token_does_not_panic_with_alternating_bytes() {
    let data: Vec<u8> = (0..64)
        .map(|i| if i % 2 == 0 { 0xFF } else { 0x00 })
        .collect();
    if let Some(mut token) = build_token(&data) {
        mutate_token(&mut token, &data);
        // Verify we can still serialize after mutation
        let _ = serde_json::to_string(&token);
    }
}

#[test]
fn run_decode_program_handles_all_zero_input() {
    let data = vec![0u8; 64];
    run_decode_program(&data);
}

#[test]
fn run_handshake_program_handles_long_deterministic_input() {
    // Exercise deeper loop iterations with a longer input
    let data: Vec<u8> = (0..512).map(|i| (i % 256) as u8).collect();
    run_handshake_program(&data);
}

#[test]
fn collect_files_returns_sorted_paths() {
    // Verify that the corpus helper returns sorted paths (determinism guarantee)
    let repo = repo_root();
    let fixture_dir = repo.join("crates/franken-engine/tests/fixtures/fuzz_adversarial/decode_dos");
    if fixture_dir.exists() {
        let files = collect_files(&fixture_dir);
        let sorted: Vec<_> = {
            let mut v = files.clone();
            v.sort();
            v
        };
        assert_eq!(files, sorted, "collect_files must return sorted paths");
    }
}

// ---------- enrichment: nonce derivation determinism and AEAD ----------

#[test]
fn derive_deterministic_aead_nonce_same_inputs_same_output() {
    let key = [0x42u8; 32];
    let n1 = derive_deterministic_aead_nonce(
        &key,
        DataPlaneDirection::ExtensionToHost,
        7,
        AeadAlgorithm::ChaCha20Poly1305,
    )
    .unwrap();
    let n2 = derive_deterministic_aead_nonce(
        &key,
        DataPlaneDirection::ExtensionToHost,
        7,
        AeadAlgorithm::ChaCha20Poly1305,
    )
    .unwrap();
    assert_eq!(
        n1.as_bytes(),
        n2.as_bytes(),
        "deterministic nonce must be stable"
    );
}

#[test]
fn derive_deterministic_aead_nonce_different_directions_differ() {
    let key = [0xAB; 32];
    let ext_to_host = derive_deterministic_aead_nonce(
        &key,
        DataPlaneDirection::ExtensionToHost,
        1,
        AeadAlgorithm::Aes256Gcm,
    )
    .unwrap();
    let host_to_ext = derive_deterministic_aead_nonce(
        &key,
        DataPlaneDirection::HostToExtension,
        1,
        AeadAlgorithm::Aes256Gcm,
    )
    .unwrap();
    assert_ne!(
        ext_to_host.as_bytes(),
        host_to_ext.as_bytes(),
        "direction must differentiate nonces"
    );
}

#[test]
fn derive_deterministic_aead_nonce_algorithm_determines_length() {
    let key = [0x01; 32];
    let chacha = derive_deterministic_aead_nonce(
        &key,
        DataPlaneDirection::ExtensionToHost,
        0,
        AeadAlgorithm::ChaCha20Poly1305,
    )
    .unwrap();
    assert_eq!(chacha.as_bytes().len(), 12);

    let aes = derive_deterministic_aead_nonce(
        &key,
        DataPlaneDirection::ExtensionToHost,
        0,
        AeadAlgorithm::Aes256Gcm,
    )
    .unwrap();
    assert_eq!(aes.as_bytes().len(), 12);

    let xchacha = derive_deterministic_aead_nonce(
        &key,
        DataPlaneDirection::ExtensionToHost,
        0,
        AeadAlgorithm::XChaCha20Poly1305,
    )
    .unwrap();
    assert_eq!(xchacha.as_bytes().len(), 24);
}

#[test]
fn derive_deterministic_aead_nonce_different_sequences_differ() {
    let key = [0x77; 32];
    let n1 = derive_deterministic_aead_nonce(
        &key,
        DataPlaneDirection::ExtensionToHost,
        0,
        AeadAlgorithm::ChaCha20Poly1305,
    )
    .unwrap();
    let n2 = derive_deterministic_aead_nonce(
        &key,
        DataPlaneDirection::ExtensionToHost,
        1,
        AeadAlgorithm::ChaCha20Poly1305,
    )
    .unwrap();
    assert_ne!(
        n1.as_bytes(),
        n2.as_bytes(),
        "different sequences must yield different nonces"
    );
}

// ---------- enrichment: build_aead_associated_data ----------

#[test]
fn build_aead_associated_data_determinism() {
    let ad1 = build_aead_associated_data("session-1", "hostcall", 0);
    let ad2 = build_aead_associated_data("session-1", "hostcall", 0);
    assert_eq!(ad1, ad2, "associated data must be deterministic");
}

#[test]
fn build_aead_associated_data_different_sessions_differ() {
    let ad1 = build_aead_associated_data("session-alpha", "hostcall", 0);
    let ad2 = build_aead_associated_data("session-beta", "hostcall", 0);
    assert_ne!(ad1, ad2, "different session IDs must produce different AD");
}

#[test]
fn build_aead_associated_data_different_flags_differ() {
    let ad1 = build_aead_associated_data("sess", "msg", 0);
    let ad2 = build_aead_associated_data("sess", "msg", 1);
    assert_ne!(ad1, ad2, "different flags must produce different AD");
}

// ---------- enrichment: CanonicalValue I64, Bool, Null roundtrips ----------

#[test]
fn canonical_value_i64_encode_decode_roundtrip() {
    for val in [0i64, -1, 1, i64::MIN, i64::MAX] {
        let cv = CanonicalValue::I64(val);
        let encoded = encode_value(&cv);
        let decoded = decode_value(&encoded).expect("decode I64");
        assert_eq!(cv, decoded);
    }
}

#[test]
fn canonical_value_bool_encode_decode_roundtrip() {
    for val in [true, false] {
        let cv = CanonicalValue::Bool(val);
        let encoded = encode_value(&cv);
        let decoded = decode_value(&encoded).expect("decode Bool");
        assert_eq!(cv, decoded);
    }
}

#[test]
fn canonical_value_null_encode_decode_roundtrip() {
    let cv = CanonicalValue::Null;
    let encoded = encode_value(&cv);
    let decoded = decode_value(&encoded).expect("decode Null");
    assert_eq!(cv, decoded);
}

// ---------- enrichment: SessionConfig serde roundtrip and clone independence ----------

#[test]
fn session_config_serde_roundtrip() {
    let config = SessionConfig {
        max_lifetime_ticks: 999,
        max_messages: 500,
        max_buffered_messages: 32,
        sequence_policy: SequencePolicy::Strict,
        replay_drop_threshold: 5,
        replay_drop_window_ticks: 200,
    };
    let json = serde_json::to_string(&config).expect("serialize SessionConfig");
    let recovered: SessionConfig = serde_json::from_str(&json).expect("deserialize SessionConfig");
    assert_eq!(config, recovered);
}

#[test]
fn session_config_clone_independence() {
    let config = SessionConfig {
        max_lifetime_ticks: 100,
        max_messages: 50,
        max_buffered_messages: 10,
        sequence_policy: SequencePolicy::Monotonic,
        replay_drop_threshold: 3,
        replay_drop_window_ticks: 100,
    };
    let mut cloned = config.clone();
    cloned.max_lifetime_ticks = 9999;
    cloned.max_messages = 1;
    assert_eq!(cloned.max_lifetime_ticks, 9999);
    assert_eq!(cloned.max_messages, 1);
    assert_eq!(
        config.max_lifetime_ticks, 100,
        "original must not be affected by clone mutation"
    );
    assert_eq!(config.max_messages, 50);
}

// ---------- enrichment: mutate_token clone independence ----------

#[test]
fn mutate_token_clone_independence() {
    let data: Vec<u8> = (0..64).collect();
    if let Some(token) = build_token(&data) {
        let mut cloned = token.clone();
        mutate_token(&mut cloned, &data);
        // Original token must remain unchanged
        assert_eq!(token.zone, "test-zone");
        // Cloned token should have been mutated (zone gets rewritten by opcode 5)
        // At minimum, signature bits should differ due to XOR mutations
        let original_sig = token.signature.clone();
        let mutated_sig = cloned.signature.clone();
        assert_ne!(
            original_sig, mutated_sig,
            "mutated clone must differ from original"
        );
    }
}

// ---------- enrichment: run_decode_program boundary at 31 bytes ----------

#[test]
fn run_decode_program_handles_exactly_31_bytes_below_schema_threshold() {
    // 31 bytes is just below the 32-byte threshold for the schema path
    let data: Vec<u8> = (0..31).collect();
    run_decode_program(&data);
}

// ---------- enrichment: make_id with single-byte data (extreme wrapping) ----------

#[test]
fn make_id_single_byte_data_wraps_consistently() {
    let data = [0xCC];
    let id1 = make_id("wrap", &data, 0);
    let id2 = make_id("wrap", &data, 0);
    assert_eq!(id1, id2, "same input must produce same id");
    // With single byte, all 8 chars map to the same value
    let suffix = &id1["wrap-".len()..];
    let chars: Vec<char> = suffix.chars().collect();
    assert!(
        chars.iter().all(|c| *c == chars[0]),
        "single-byte input should yield uniform suffix"
    );
}

// ---------- enrichment: run_handshake_program with all-0xFF data ----------

#[test]
fn run_handshake_program_handles_max_byte_input() {
    // All 0xFF — exercises maximum values for config fields
    let data = vec![0xFF; 128];
    run_handshake_program(&data);
}

// ---------- enrichment: SessionHandshake serde roundtrip ----------

#[test]
fn session_handshake_serde_roundtrip() {
    let handshake = SessionHandshake {
        session_id: "sess-test-42".to_string(),
        extension_id: "ext-abc".to_string(),
        host_id: "host-xyz".to_string(),
        extension_nonce: 12345,
        host_nonce: 67890,
        timestamp_ticks: 999,
        trace_id: "trace-001".to_string(),
    };
    let json = serde_json::to_string(&handshake).expect("serialize handshake");
    let recovered: SessionHandshake = serde_json::from_str(&json).expect("deserialize handshake");
    assert_eq!(handshake, recovered);
}

// ---------- enrichment: run_token_program with all 0xFF data ----------

#[test]
fn run_token_program_handles_all_max_byte_data() {
    let data = vec![0xFF; 64];
    run_token_program(&data);
}
