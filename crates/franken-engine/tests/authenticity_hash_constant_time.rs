#![forbid(unsafe_code)]

use frankenengine_engine::hash_tiers::AuthenticityHash;

const VERIFIER_SOURCE_CONTRACTS: &[(&str, &str, &str)] = &[
    (
        "fleet_convergence.rs",
        include_str!("../src/fleet_convergence.rs"),
        "self.signature.constant_time_eq(&expected)",
    ),
    (
        "translation_validation.rs",
        include_str!("../src/translation_validation.rs"),
        "self.signature.constant_time_eq(&expected)",
    ),
    (
        "proof_schema.rs opt receipt",
        include_str!("../src/proof_schema.rs"),
        "self.signature.constant_time_eq(&expected)",
    ),
    (
        "proof_schema.rs rollback token",
        include_str!("../src/proof_schema.rs"),
        "self.issuer_signature.constant_time_eq(&expected)",
    ),
    (
        "translation_validation_receipt.rs",
        include_str!("../src/translation_validation_receipt.rs"),
        "self.signature.constant_time_eq(&expected)",
    ),
];

const FORBIDDEN_EARLY_EXIT_PATTERNS: &[&str] = &[
    "signature == expected",
    "issuer_signature == expected",
    "signature == expected_signature",
    "expected == self.signature",
    "expected == self.issuer_signature",
];

#[test]
fn keyed_hash_verifiers_keep_constant_time_source_contract() {
    for (name, source, required_call) in VERIFIER_SOURCE_CONTRACTS {
        assert!(
            source.contains(required_call),
            "{name} must keep keyed-hash verification on `{required_call}`"
        );
    }

    for (name, source, _) in VERIFIER_SOURCE_CONTRACTS {
        for forbidden in FORBIDDEN_EARLY_EXIT_PATTERNS {
            assert!(
                !source.contains(forbidden),
                "{name} must not use early-exit PartialEq pattern `{forbidden}` for keyed hashes"
            );
        }
    }
}

#[test]
fn authenticity_hash_single_byte_mutation_metamorphic_rejects_every_position() {
    let base = AuthenticityHash::compute_keyed(
        b"bd-2cyl5-metamorphic-key",
        b"bd-2cyl5-metamorphic-payload",
    );
    let mut rejected_positions = Vec::new();

    for index in 0..base.as_bytes().len() {
        let mut mutated = *base.as_bytes();
        mutated[index] ^= 0x80;
        let tampered = AuthenticityHash(mutated);
        rejected_positions.push((
            index,
            base.constant_time_eq(&tampered),
            tampered.constant_time_eq(&base),
        ));
    }

    assert_eq!(rejected_positions.len(), 32);
    assert!(
        rejected_positions
            .iter()
            .all(|(_, forward, reverse)| !forward && !reverse),
        "every one-byte tag mutation must be rejected symmetrically: {rejected_positions:?}"
    );
}
