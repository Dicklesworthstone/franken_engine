#![no_main]

use frankenengine_extension_host::{
    DecisionPublicKey, DecisionSigningKey, PolicySignError, PolicySignSurface,
};
use libfuzzer_sys::fuzz_target;

const MAX_INPUT_BYTES: usize = 4096;
const MAX_KEY_BYTES: usize = 96;
const MAX_SIGNATURE_BYTES: usize = 128;
const MAX_PAYLOAD_BYTES: usize = 512;
const POLICY_SIGN_FAIL_CLOSED_ERROR_CODE: &str = "FE-DECLASS-0009";

struct FuzzInput<'a> {
    key_bytes: &'a [u8],
    signature: &'a [u8],
    payload: &'a [u8],
    alternate_payload: &'a [u8],
    public_key_bytes: [u8; 32],
}

fuzz_target!(|data: &[u8]| {
    if data.len() > MAX_INPUT_BYTES {
        return;
    }

    let input = FuzzInput::parse(data);
    exercise_decision_signing_key_import(&input);
    exercise_arbitrary_public_key_verify(&input);
});

impl<'a> FuzzInput<'a> {
    fn parse(data: &'a [u8]) -> Self {
        let mut cursor = 0;
        let key_len = read_len(data, &mut cursor, MAX_KEY_BYTES);
        let key_bytes = take(data, &mut cursor, key_len);

        let signature_len = read_len(data, &mut cursor, MAX_SIGNATURE_BYTES);
        let signature = take(data, &mut cursor, signature_len);

        let payload_len = read_len(data, &mut cursor, MAX_PAYLOAD_BYTES);
        let payload = take(data, &mut cursor, payload_len);

        let alternate_payload_len = read_len(data, &mut cursor, MAX_PAYLOAD_BYTES);
        let alternate_payload = take(data, &mut cursor, alternate_payload_len);

        let mut public_key_bytes = [0_u8; 32];
        let available_public_key_bytes = take(data, &mut cursor, 32);
        public_key_bytes[..available_public_key_bytes.len()]
            .copy_from_slice(available_public_key_bytes);

        Self {
            key_bytes,
            signature,
            payload,
            alternate_payload,
            public_key_bytes,
        }
    }
}

fn exercise_decision_signing_key_import(input: &FuzzInput<'_>) {
    match DecisionSigningKey::try_from_bytes(input.key_bytes) {
        Ok(signing_key) => {
            assert_eq!(input.key_bytes.len(), 32);

            let public_key = signing_key.public_key();
            let signature = signing_key.sign(input.payload);
            assert_eq!(signature.len(), 64);
            assert!(public_key.verify(input.payload, &signature));

            let mut corrupted_signature = signature.clone();
            corrupted_signature[0] ^= 0x80;
            assert!(!public_key.verify(input.payload, &corrupted_signature));

            if input.payload != input.alternate_payload {
                assert!(!public_key.verify(input.alternate_payload, &signature));
            }

            if input.signature.len() != 64 {
                assert!(!public_key.verify(input.payload, input.signature));
            } else {
                let _ = public_key.verify(input.payload, input.signature);
            }
        }
        Err(error) => {
            assert_ne!(input.key_bytes.len(), 32);
            assert_decision_key_fail_closed(input.key_bytes.len(), &error);
        }
    }
}

fn exercise_arbitrary_public_key_verify(input: &FuzzInput<'_>) {
    let public_key = public_key_from_bytes(input.public_key_bytes);
    if input.signature.len() != 64 {
        assert!(!public_key.verify(input.payload, input.signature));
        return;
    }

    let _ = public_key.verify(input.payload, input.signature);
}

fn assert_decision_key_fail_closed(actual_len: usize, error: &PolicySignError) {
    assert_eq!(error.error_code(), POLICY_SIGN_FAIL_CLOSED_ERROR_CODE);
    assert_eq!(error.request_id(), "decision_signing_key");

    match error {
        PolicySignError::FailClosed {
            surface, detail, ..
        } => {
            assert_eq!(*surface, PolicySignSurface::DecisionSigningKey);
            assert!(detail.contains("expected 32 signing key bytes"));
            assert!(detail.contains(&actual_len.to_string()));
        }
        other => panic!("DecisionSigningKey byte import should fail closed, got {other:?}"),
    }
}

fn public_key_from_bytes(bytes: [u8; 32]) -> DecisionPublicKey {
    serde_json::from_value(serde_json::json!({ "bytes": bytes }))
        .expect("DecisionPublicKey JSON fixture should decode")
}

fn read_len(data: &[u8], cursor: &mut usize, max_len: usize) -> usize {
    let raw = data.get(*cursor).copied().unwrap_or(0) as usize;
    *cursor = (*cursor).saturating_add(1);
    raw % (max_len + 1)
}

fn take<'a>(data: &'a [u8], cursor: &mut usize, requested_len: usize) -> &'a [u8] {
    let start = (*cursor).min(data.len());
    let end = start.saturating_add(requested_len).min(data.len());
    *cursor = end;
    &data[start..end]
}
