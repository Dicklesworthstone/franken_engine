//! Public-key admission shared by publisher manifests and policy receipts.
//!
//! An externally supplied key is not trustworthy merely because its compressed
//! point decodes. Weak Ed25519 keys permit signatures without a signing secret.
//! Trust-root selection remains the caller's responsibility; this module only
//! enforces key validity and strict verification at every cryptographic boundary.

use super::{DecisionPublicKey, DecisionSigningKey};
use ed25519_dalek::VerifyingKey;
use serde::{Deserialize, Deserializer};
use std::fmt;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DecisionPublicKeyError {
    InvalidLength { actual: usize },
    InvalidEncoding,
    WeakKey,
}

impl fmt::Display for DecisionPublicKeyError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidLength { actual } => {
                write!(f, "expected 32 decision public-key bytes, got {actual}")
            }
            Self::InvalidEncoding => f.write_str("invalid or noncanonical Ed25519 public key"),
            Self::WeakKey => f.write_str("weak Ed25519 public key is not an authority"),
        }
    }
}

impl std::error::Error for DecisionPublicKeyError {}

pub(super) fn checked_verifying_key(
    bytes: &[u8; 32],
) -> Result<VerifyingKey, DecisionPublicKeyError> {
    let key =
        VerifyingKey::from_bytes(bytes).map_err(|_| DecisionPublicKeyError::InvalidEncoding)?;
    // from_bytes follows ZIP-215 and accepts noncanonical point encodings.
    // Recompress the decoded point rather than treating such aliases as distinct
    // trust-root identities. This delegates curve arithmetic to dalek.
    if key.to_edwards().compress().to_bytes() != *bytes {
        return Err(DecisionPublicKeyError::InvalidEncoding);
    }
    if key.is_weak() {
        return Err(DecisionPublicKeyError::WeakKey);
    }
    Ok(key)
}

impl DecisionPublicKey {
    /// Import a canonical, non-weak key. This validates the key, not its owner.
    pub fn try_from_bytes(bytes: &[u8]) -> Result<Self, DecisionPublicKeyError> {
        let bytes: [u8; 32] =
            bytes
                .try_into()
                .map_err(|_| DecisionPublicKeyError::InvalidLength {
                    actual: bytes.len(),
                })?;
        checked_verifying_key(&bytes)?;
        Ok(Self { bytes })
    }

    /// Public verification material; safe to persist with authenticated evidence.
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.bytes
    }
}

impl<'de> Deserialize<'de> for DecisionPublicKey {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        #[derive(Deserialize)]
        #[serde(deny_unknown_fields)]
        struct WireKey {
            bytes: [u8; 32],
        }
        let wire = WireKey::deserialize(deserializer)?;
        Self::try_from_bytes(&wire.bytes).map_err(serde::de::Error::custom)
    }
}

impl fmt::Debug for DecisionSigningKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("DecisionSigningKey")
            .field("bytes", &"[REDACTED]")
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        Capability, CapabilityEscrowDecisionKind, CapabilityEscrowDecisionReceipt,
        CapabilityEscrowState, CryptographicDecisionReceipt, DecisionVerdict, DelegateCellFactory,
        EmergencyGrantArtifact, ExtensionHostConfig, ExtensionManifest, ManifestValidationError,
        compute_content_hash, validate_manifest_with_config, verify_manifest_signature,
    };
    use ed25519_dalek::{Signature, Signer, SigningKey, Verifier};
    use std::collections::{BTreeMap, BTreeSet};

    fn identity_key() -> [u8; 32] {
        let mut bytes = [0; 32];
        bytes[0] = 1;
        bytes
    }

    // R = identity, S = 0. No private key was used to make these bytes.
    fn identity_signature() -> Vec<u8> {
        let mut signature = vec![0; 64];
        signature[0] = 1;
        signature
    }

    fn manifest() -> ExtensionManifest {
        let mut manifest = ExtensionManifest {
            name: "publisher-test".into(),
            version: "1.0.0".into(),
            entrypoint: "index.js".into(),
            capabilities: BTreeSet::from([Capability::FsRead]),
            publisher_signature: None,
            content_hash: [0; 32],
            trust_chain_ref: Some("trusted-publisher".into()),
            min_engine_version: crate::CURRENT_ENGINE_VERSION.into(),
        };
        manifest.content_hash = compute_content_hash(&manifest).unwrap();
        manifest
    }

    #[test]
    fn permissive_weak_key_forgery_is_rejected_by_host_verification() {
        let bytes = identity_key();
        let signature = identity_signature();
        let permissive = VerifyingKey::from_bytes(&bytes).unwrap();
        let sig = Signature::from_slice(&signature).unwrap();
        assert!(permissive.is_weak());
        // Demonstrate the old failure mode against two unrelated messages.
        for message in [
            b"approve secret release".as_slice(),
            b"approve hostile extension",
        ] {
            assert!(permissive.verify(message, &sig).is_ok());
            // Defense in depth also covers internally built invalid key values.
            assert!(!DecisionPublicKey { bytes }.verify(message, &signature));
        }
    }

    #[test]
    fn imported_and_deserialized_weak_keys_are_rejected() {
        for bytes in [identity_key(), [0; 32]] {
            assert!(DecisionPublicKey::try_from_bytes(&bytes).is_err());
            let encoded = serde_json::json!({"bytes": bytes});
            assert!(serde_json::from_value::<DecisionPublicKey>(encoded).is_err());
        }
    }

    #[test]
    fn noncanonical_point_aliases_are_not_distinct_authorities() {
        // p + 1 decodes to the identity under ZIP-215.
        let mut alias = [0xff; 32];
        alias[0] = 0xee;
        alias[31] = 0x7f;
        assert_eq!(
            DecisionPublicKey::try_from_bytes(&alias),
            Err(DecisionPublicKeyError::InvalidEncoding)
        );
        let mut negative_zero = identity_key();
        negative_zero[31] = 0x80;
        assert!(DecisionPublicKey::try_from_bytes(&negative_zero).is_err());
    }

    #[test]
    fn public_key_import_requires_exact_length() {
        for count in [0, 1, 31, 33, 64, 4096] {
            assert_eq!(
                DecisionPublicKey::try_from_bytes(&vec![0; count]),
                Err(DecisionPublicKeyError::InvalidLength { actual: count })
            );
        }
    }

    #[test]
    fn generated_public_keys_round_trip_without_changing_signatures() {
        for seed in [0, 1, 42, 127, 255] {
            let signing = DecisionSigningKey::new([seed; 32]);
            let public = signing.public_key();
            let imported = DecisionPublicKey::try_from_bytes(public.as_bytes()).unwrap();
            let decoded: DecisionPublicKey =
                serde_json::from_slice(&serde_json::to_vec(&public).unwrap()).unwrap();
            assert_eq!(public, imported);
            assert_eq!(public, decoded);
            let signature = signing.sign(b"bound evidence");
            assert!(decoded.verify(b"bound evidence", &signature));
            assert!(!decoded.verify(b"other evidence", &signature));
        }
    }

    #[test]
    fn malformed_key_envelopes_are_rejected() {
        let bytes = DecisionSigningKey::new([7; 32]).public_key().bytes;
        let array = serde_json::to_string(&bytes).unwrap();
        for json in [
            "{}".to_string(),
            format!("{{\"bytes\":{array},\"bytes\":{array}}}"),
            format!("{{\"bytes\":{array},\"authority\":\"admin\"}}"),
        ] {
            assert!(serde_json::from_str::<DecisionPublicKey>(&json).is_err());
        }
    }

    #[test]
    fn trusted_weak_publisher_cannot_admit_a_forged_manifest() {
        let mut manifest = manifest();
        manifest.publisher_signature = Some(identity_signature());
        let key_hex = crate::bytes_to_hex(&identity_key());
        let config = ExtensionHostConfig {
            trusted_publisher_keys: BTreeMap::from([("trusted-publisher".into(), key_hex.clone())]),
            ..ExtensionHostConfig::default()
        };
        assert!(!verify_manifest_signature(
            &manifest,
            &key_hex,
            &identity_signature()
        ));
        assert_eq!(
            validate_manifest_with_config(&manifest, &config),
            Err(ManifestValidationError::InvalidPublisherSignature)
        );
    }

    #[test]
    fn trusted_real_publisher_still_admits_and_tampering_fails() {
        let mut manifest = manifest();
        let signer = SigningKey::from_bytes(&[19; 32]);
        let key_hex = crate::bytes_to_hex(&signer.verifying_key().to_bytes());
        manifest.publisher_signature = Some(
            signer
                .sign(&crate::domain_separated_manifest_payload(
                    &manifest.content_hash,
                ))
                .to_bytes()
                .to_vec(),
        );
        let config = ExtensionHostConfig {
            trusted_publisher_keys: BTreeMap::from([("trusted-publisher".into(), key_hex)]),
            ..ExtensionHostConfig::default()
        };
        validate_manifest_with_config(&manifest, &config).unwrap();
        manifest.entrypoint = "replacement.js".into();
        manifest.content_hash = compute_content_hash(&manifest).unwrap();
        assert_eq!(
            validate_manifest_with_config(&manifest, &config),
            Err(ManifestValidationError::InvalidPublisherSignature)
        );
    }

    #[test]
    fn forged_weak_key_policy_artifacts_are_rejected_on_all_surfaces() {
        let signer = DecisionSigningKey::new([29; 32]);
        let invalid = DecisionPublicKey {
            bytes: identity_key(),
        };
        let mut receipt = CryptographicDecisionReceipt::new_signed(
            "request",
            DecisionVerdict::Approved { conditions: vec![] },
            vec![],
            vec![],
            500_000,
            10,
            &signer,
        )
        .unwrap();
        let mut escrow = CapabilityEscrowDecisionReceipt::new_signed(
            "request",
            "extension",
            Capability::NetClient,
            CapabilityEscrowDecisionKind::Challenge,
            CapabilityEscrowState::Challenged,
            "trace".into(),
            "replay".into(),
            "decision",
            "policy",
            "witness".into(),
            vec![],
            vec![],
            "escrowed".into(),
            None,
            10,
            &signer,
        )
        .unwrap();
        let mut grant = EmergencyGrantArtifact::new_signed(
            "request",
            "extension",
            Capability::FsWrite,
            "emergency".into(),
            "operator".into(),
            20,
            1,
            true,
            true,
            10,
            &signer,
        )
        .unwrap();
        assert!(receipt.verify(&signer.public_key()));
        assert!(escrow.verify(&signer.public_key()));
        assert!(grant.verify(&signer.public_key()));
        receipt.signature = identity_signature();
        escrow.signature = identity_signature();
        grant.signature = identity_signature();
        assert!(!receipt.verify(&invalid));
        assert!(!escrow.verify(&invalid));
        assert!(!grant.verify(&invalid));
    }

    #[test]
    fn debug_never_exposes_signing_material_in_nested_factory() {
        let key = DecisionSigningKey::new([171; 32]);
        assert_eq!(
            format!("{key:?}"),
            "DecisionSigningKey { bytes: \"[REDACTED]\" }"
        );
        let mut factory = DelegateCellFactory::test_default();
        factory.decision_signing_key = key;
        let debug = format!("{factory:#?}");
        assert!(debug.contains("[REDACTED]"));
        assert!(!debug.contains("171"));
    }
}
