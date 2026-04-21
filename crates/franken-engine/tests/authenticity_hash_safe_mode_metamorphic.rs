#![forbid(unsafe_code)]

use frankenengine_engine::hash_tiers::{AuthenticityHash, HashError};

const KEY: &[u8] = b"bd-22jta-safe-mode-key";
const DATA: &[u8] = b"bd-22jta-safe-mode-payload";

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
