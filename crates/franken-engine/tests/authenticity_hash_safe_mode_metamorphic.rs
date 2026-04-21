#![forbid(unsafe_code)]

use frankenengine_engine::hash_tiers::{AuthenticityHash, HashAlgorithm, HashError};

const KEY: &[u8] = b"bd-22jta-safe-mode-key";
const DATA: &[u8] = b"bd-22jta-safe-mode-payload";

fn assert_keyed_hash_unavailable_round_trips(err: HashError, expected_reason: &str) {
    let json = serde_json::to_string(&err).expect("hash errors serialize");
    let restored: HashError = serde_json::from_str(&json).expect("hash errors deserialize");
    assert_eq!(restored, err, "safe-mode hash errors must be serde-stable");

    match err {
        HashError::KeyedHashUnavailable { algorithm, reason } => {
            assert_eq!(algorithm, HashAlgorithm::SipInspiredKeyed);
            assert!(
                reason.contains(expected_reason),
                "expected reason containing {expected_reason:?}, got {reason:?}"
            );
        }
        other => panic!("expected keyed-hash safe-mode error, got {other:?}"),
    }
}

#[test]
fn try_compute_keyed_matches_infallible_wrapper_equivalence_mr() {
    let infallible = AuthenticityHash::compute_keyed(KEY, DATA);
    let fallible =
        AuthenticityHash::try_compute_keyed(KEY, DATA).expect("HMAC-SHA256 accepts test key");

    assert_eq!(
        fallible, infallible,
        "fallible safe-mode API must be equivalent to the infallible wrapper on valid inputs"
    );
}

#[test]
fn try_compute_keyed_rejects_invalid_safe_mode_keys_mr() {
    let cases = [
        (Vec::new(), "empty key"),
        (vec![0xa5; 4097], "exceeds maximum"),
    ];

    for (key, expected_reason) in cases {
        let err = AuthenticityHash::try_compute_keyed(&key, DATA)
            .expect_err("invalid safe-mode key must fail closed");
        assert_keyed_hash_unavailable_round_trips(err, expected_reason);
    }
}

#[test]
fn safe_keyed_verify_rejects_invalid_key_before_tag_shape_mr() {
    let err = AuthenticityHash::safe_keyed_verify(b"", DATA, &[0u8; 1])
        .expect_err("local key misconfiguration should fail closed deterministically");
    assert_keyed_hash_unavailable_round_trips(err, "empty key");
}

#[test]
fn safe_keyed_verify_malformed_length_enters_safe_mode_mr() {
    let valid = AuthenticityHash::compute_keyed(KEY, DATA);
    let malformed_lengths = [0usize, 1, 7, 16, 31, 33, 64];

    for len in malformed_lengths {
        let mut candidate = valid.as_bytes().to_vec();
        candidate.resize(len, 0xa5);

        let err = AuthenticityHash::safe_keyed_verify(KEY, DATA, &candidate)
            .expect_err("malformed authenticity tag length must fail closed");
        assert_eq!(
            err,
            HashError::InvalidAuthenticityTagLength {
                expected: 32,
                actual: len
            },
            "length mutation should map to deterministic safe-mode error"
        );
    }
}

#[test]
fn safe_keyed_verify_single_byte_mutation_rejects_without_error_mr() {
    let valid = AuthenticityHash::compute_keyed(KEY, DATA);
    assert!(
        AuthenticityHash::safe_keyed_verify(KEY, DATA, valid.as_bytes()).unwrap(),
        "baseline tag must verify before metamorphic mutation"
    );

    let mut rejected_positions = Vec::new();
    for index in 0..valid.as_bytes().len() {
        let mut candidate = *valid.as_bytes();
        candidate[index] ^= 0x80;
        rejected_positions.push((
            index,
            AuthenticityHash::safe_keyed_verify(KEY, DATA, &candidate),
        ));
    }

    assert_eq!(rejected_positions.len(), 32);
    assert!(
        rejected_positions
            .iter()
            .all(|(_, outcome)| matches!(outcome, Ok(false))),
        "same-length tag mutations should reject without entering error fallback: {rejected_positions:?}"
    );
}
