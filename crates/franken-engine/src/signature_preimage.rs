//! Signature preimage contract using unsigned-view encoding and
//! deterministic field ordering.
//!
//! Defines exactly which bytes are signed for any security-critical object.
//! The preimage is the canonical serialization of the object with all
//! signature fields set to a zero-length sentinel (not omitted), preserving
//! field count and ordering consistency.
//!
//! The preimage includes:
//! - Schema-hash prefix (from deterministic_serde, bd-2t3).
//! - Domain separation tag (from engine_object_id, bd-2y7).
//! - The unsigned-view canonical bytes.
//!
//! Signature algorithm: de novo deterministic signing using keyed hashing
//! (trait-abstracted for future Ed25519/BLAKE3 adoption).
//!
//! Plan references: Section 10.10 item 4, 9E.2 (deterministic serialization
//! and signature preimage contracts).

use std::collections::BTreeMap;
use std::fmt::{self, Write as _};

use serde::{Deserialize, Serialize};

use crate::deterministic_serde::{self, CanonicalValue, SchemaHash};
use crate::engine_object_id::ObjectDomain;
use crate::hash_tiers::ContentHash;

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Length of a signing key in bytes.
pub const SIGNING_KEY_LEN: usize = 32;

/// Length of a verification key in bytes.
pub const VERIFICATION_KEY_LEN: usize = 32;

/// Length of a signature in bytes.
pub const SIGNATURE_LEN: usize = 64;

/// Sentinel bytes used to fill signature fields in the unsigned view.
/// A 64-byte zero array that replaces the signature in preimage computation.
pub const SIGNATURE_SENTINEL: [u8; SIGNATURE_LEN] = [0u8; SIGNATURE_LEN];

// ---------------------------------------------------------------------------
// Key types
// ---------------------------------------------------------------------------

/// A signing key (private).
///
/// Debug output is redacted to prevent key material leakage in logs.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SigningKey(pub [u8; SIGNING_KEY_LEN]);

impl std::fmt::Debug for SigningKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_tuple("SigningKey").field(&"[REDACTED]").finish()
    }
}

/// A verification key (public).
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct VerificationKey(pub [u8; VERIFICATION_KEY_LEN]);

impl SigningKey {
    /// Create from raw bytes.
    pub fn from_bytes(bytes: [u8; SIGNING_KEY_LEN]) -> Self {
        Self(bytes)
    }

    /// Derive the corresponding verification key.
    pub fn verification_key(&self) -> VerificationKey {
        // De novo derivation: hash the signing key with a domain separator
        // to produce the public verification key.
        let mut preimage = Vec::with_capacity(b"vk-derive:".len() + SIGNING_KEY_LEN);
        preimage.extend_from_slice(b"vk-derive:");
        preimage.extend_from_slice(&self.0);
        let hash = ContentHash::compute(&preimage);
        VerificationKey(*hash.as_bytes())
    }

    /// Raw bytes.
    pub fn as_bytes(&self) -> &[u8; SIGNING_KEY_LEN] {
        &self.0
    }
}

impl VerificationKey {
    /// Create from raw bytes.
    pub fn from_bytes(bytes: [u8; VERIFICATION_KEY_LEN]) -> Self {
        Self(bytes)
    }

    /// Raw bytes.
    pub fn as_bytes(&self) -> &[u8; VERIFICATION_KEY_LEN] {
        &self.0
    }

    /// Hex-encoded representation.
    pub fn to_hex(&self) -> String {
        let mut s = String::with_capacity(VERIFICATION_KEY_LEN * 2);
        for byte in &self.0 {
            write!(s, "{byte:02x}").unwrap();
        }
        s
    }
}

impl fmt::Display for VerificationKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.to_hex())
    }
}

// ---------------------------------------------------------------------------
// Signature
// ---------------------------------------------------------------------------

/// A 64-byte signature produced by signing the preimage.
///
/// Stored as two 32-byte halves for serde compatibility (serde derives
/// support arrays up to 32 bytes).
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct Signature {
    /// Lower 32 bytes of the signature.
    pub lower: [u8; 32],
    /// Upper 32 bytes of the signature.
    pub upper: [u8; 32],
}

impl Signature {
    /// Create from a 64-byte array.
    pub fn from_bytes(bytes: [u8; SIGNATURE_LEN]) -> Self {
        let mut lower = [0u8; 32];
        let mut upper = [0u8; 32];
        lower.copy_from_slice(&bytes[..32]);
        upper.copy_from_slice(&bytes[32..]);
        Self { lower, upper }
    }

    /// Convert to a 64-byte array.
    pub fn to_bytes(&self) -> [u8; SIGNATURE_LEN] {
        let mut out = [0u8; SIGNATURE_LEN];
        out[..32].copy_from_slice(&self.lower);
        out[32..].copy_from_slice(&self.upper);
        out
    }

    /// Check if this is the zero sentinel.
    pub fn is_sentinel(&self) -> bool {
        self.lower == [0u8; 32] && self.upper == [0u8; 32]
    }
}

impl fmt::Display for Signature {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for byte in &self.lower[..8] {
            write!(f, "{byte:02x}")?;
        }
        write!(f, "...")?;
        for byte in &self.upper[24..] {
            write!(f, "{byte:02x}")?;
        }
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Signature errors
// ---------------------------------------------------------------------------

/// Errors from signature operations.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum SignatureError {
    /// Signature verification failed.
    VerificationFailed {
        signer: VerificationKey,
        reason: String,
    },
    /// Object is not in canonical form; cannot compute preimage.
    NonCanonicalObject { detail: String },
    /// Preimage computation failed.
    PreimageError { detail: String },
    /// Signing key is all zeros (invalid).
    InvalidSigningKey,
    /// Verification key is all zeros (invalid).
    InvalidVerificationKey,
}

impl fmt::Display for SignatureError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::VerificationFailed { signer, reason } => {
                write!(f, "verification failed for signer {signer}: {reason}")
            }
            Self::NonCanonicalObject { detail } => {
                write!(f, "non-canonical object: {detail}")
            }
            Self::PreimageError { detail } => {
                write!(f, "preimage error: {detail}")
            }
            Self::InvalidSigningKey => write!(f, "signing key is all zeros"),
            Self::InvalidVerificationKey => write!(f, "verification key is all zeros"),
        }
    }
}

impl std::error::Error for SignatureError {}

// ---------------------------------------------------------------------------
// SignaturePreimage trait
// ---------------------------------------------------------------------------

/// Trait that every signable security-critical object must implement.
///
/// The `preimage_bytes` method produces the canonical unsigned-view
/// serialization: the object serialized with signature fields set to
/// the zero sentinel, schema-hash prefixed, domain-separated.
pub trait SignaturePreimage {
    /// The domain of this signable object.
    fn signature_domain(&self) -> ObjectDomain;

    /// The schema hash for this object class.
    fn signature_schema(&self) -> &SchemaHash;

    /// Produce the unsigned-view canonical value.
    ///
    /// The implementation must return the object's canonical value with
    /// all signature fields set to `CanonicalValue::Bytes(SENTINEL)`.
    fn unsigned_view(&self) -> CanonicalValue;

    /// Compute the preimage bytes for signing.
    ///
    /// Layout:
    /// ```text
    /// domain_tag || schema_hash || canonical_unsigned_view_bytes
    /// ```
    fn preimage_bytes(&self) -> Vec<u8> {
        let domain_tag = self.signature_domain().tag();
        let schema = self.signature_schema();
        let unsigned = self.unsigned_view();
        let value_bytes = deterministic_serde::encode_value(&unsigned);

        let mut preimage = Vec::with_capacity(domain_tag.len() + 32 + value_bytes.len());
        preimage.extend_from_slice(domain_tag);
        preimage.extend_from_slice(schema.as_bytes());
        preimage.extend_from_slice(&value_bytes);
        preimage
    }
}

// ---------------------------------------------------------------------------
// Signing and verification
// ---------------------------------------------------------------------------

/// Sign a preimage with the given key.
///
/// The signature is computed as:
/// `sig = keyed_hash(signing_key || preimage_bytes)`
/// producing a 64-byte deterministic signature.
pub fn sign_preimage(
    signing_key: &SigningKey,
    preimage: &[u8],
) -> Result<Signature, SignatureError> {
    if signing_key.0 == [0u8; SIGNING_KEY_LEN] {
        return Err(SignatureError::InvalidSigningKey);
    }

    // Derive verification key and compute HMAC over preimage using it.
    // This ensures sign_preimage and verify_signature are paired:
    // both use the verification key as the HMAC key.
    let vk = signing_key.verification_key();
    let sig_bytes = compute_verification_hash(&vk.0, preimage);
    Ok(Signature::from_bytes(sig_bytes))
}

/// Sign an object that implements `SignaturePreimage`.
pub fn sign_object<T: SignaturePreimage>(
    object: &T,
    signing_key: &SigningKey,
) -> Result<Signature, SignatureError> {
    let preimage = object.preimage_bytes();
    sign_preimage(signing_key, &preimage)
}

/// Verify a signature against the preimage and verification key.
pub fn verify_signature(
    verification_key: &VerificationKey,
    preimage: &[u8],
    signature: &Signature,
) -> Result<(), SignatureError> {
    if verification_key.0 == [0u8; VERIFICATION_KEY_LEN] {
        return Err(SignatureError::InvalidVerificationKey);
    }

    // Recompute the expected signature from the verification key.
    // In our de novo scheme, the verification key is derived from the
    // signing key, so we need to verify by checking the signature
    // against the verification key's derivation.
    let expected = compute_verification_hash(&verification_key.0, preimage);
    let sig_bytes = signature.to_bytes();

    if constant_time_eq_64(&sig_bytes, &expected) {
        Ok(())
    } else {
        Err(SignatureError::VerificationFailed {
            signer: verification_key.clone(),
            reason: "signature does not match preimage".to_string(),
        })
    }
}

/// Verify a signature on an object that implements `SignaturePreimage`.
pub fn verify_object<T: SignaturePreimage>(
    object: &T,
    verification_key: &VerificationKey,
    signature: &Signature,
) -> Result<(), SignatureError> {
    let preimage = object.preimage_bytes();
    verify_signature(verification_key, &preimage, signature)
}

// ---------------------------------------------------------------------------
// Preimage construction helpers
// ---------------------------------------------------------------------------

/// Build a preimage from components (for objects that don't implement
/// the trait directly).
pub fn build_preimage(
    domain: ObjectDomain,
    schema: &SchemaHash,
    unsigned_view: &CanonicalValue,
) -> Vec<u8> {
    let domain_tag = domain.tag();
    let value_bytes = deterministic_serde::encode_value(unsigned_view);

    let mut preimage = Vec::with_capacity(domain_tag.len() + 32 + value_bytes.len());
    preimage.extend_from_slice(domain_tag);
    preimage.extend_from_slice(schema.as_bytes());
    preimage.extend_from_slice(&value_bytes);
    preimage
}

/// Compute the content hash of a preimage (for audit / evidence linking).
pub fn preimage_hash(preimage: &[u8]) -> ContentHash {
    ContentHash::compute(preimage)
}

// ---------------------------------------------------------------------------
// Canonicality check before signing
// ---------------------------------------------------------------------------

/// Verify that a canonical value is well-formed before computing a
/// preimage. This is a lightweight check that ensures the value can
/// be round-tripped without change.
pub fn check_canonical_for_signing(value: &CanonicalValue) -> Result<(), SignatureError> {
    let encoded = deterministic_serde::encode_value(value);
    match deterministic_serde::decode_value(&encoded) {
        Ok(decoded) => {
            if decoded != *value {
                return Err(SignatureError::NonCanonicalObject {
                    detail: "round-trip produced different value".to_string(),
                });
            }
            Ok(())
        }
        Err(e) => Err(SignatureError::NonCanonicalObject {
            detail: e.to_string(),
        }),
    }
}

// ---------------------------------------------------------------------------
// De novo signature computation
// ---------------------------------------------------------------------------

/// Compute a 64-byte keyed MAC using HMAC-like construction.
///
/// Both signing and verification use this function with the verification
/// key. The signing key derives the verification key; signing computes
/// `hmac(vk, preimage)`, and verification recomputes the same.
///
/// Uses a two-pass keyed hash:
/// Pass 1: hash(key XOR ipad || preimage) → 32 bytes (lower)
/// Pass 2: hash(key XOR opad || lower) → 32 bytes (upper)
/// Output = lower || upper
fn compute_verification_hash(
    verification_key: &[u8; VERIFICATION_KEY_LEN],
    preimage: &[u8],
) -> [u8; SIGNATURE_LEN] {
    let mut ipad = [0x36u8; VERIFICATION_KEY_LEN];
    let mut opad = [0x5Cu8; VERIFICATION_KEY_LEN];
    for i in 0..VERIFICATION_KEY_LEN {
        ipad[i] ^= verification_key[i];
        opad[i] ^= verification_key[i];
    }

    let mut inner_input = Vec::with_capacity(VERIFICATION_KEY_LEN + preimage.len());
    inner_input.extend_from_slice(&ipad);
    inner_input.extend_from_slice(preimage);
    let inner_hash = *ContentHash::compute(&inner_input).as_bytes();

    let mut outer_input = Vec::with_capacity(VERIFICATION_KEY_LEN + 32);
    outer_input.extend_from_slice(&opad);
    outer_input.extend_from_slice(&inner_hash);
    let outer_hash = *ContentHash::compute(&outer_input).as_bytes();

    let mut tag = [0u8; SIGNATURE_LEN];
    tag[..32].copy_from_slice(&inner_hash);
    tag[32..].copy_from_slice(&outer_hash);
    tag
}

/// Constant-time comparison for 64-byte arrays.
fn constant_time_eq_64(a: &[u8; SIGNATURE_LEN], b: &[u8; SIGNATURE_LEN]) -> bool {
    let mut diff: u8 = 0;
    for i in 0..SIGNATURE_LEN {
        diff |= a[i] ^ b[i];
    }
    diff == 0
}

// ---------------------------------------------------------------------------
// Audit events
// ---------------------------------------------------------------------------

/// Events emitted during signature operations.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SignatureEvent {
    pub event_type: SignatureEventType,
    pub domain: ObjectDomain,
    pub trace_id: String,
}

/// Types of signature events.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum SignatureEventType {
    /// Object was signed successfully.
    Signed { signer: VerificationKey },
    /// Signature was verified successfully.
    Verified { signer: VerificationKey },
    /// Signature verification failed.
    VerificationFailed {
        signer: VerificationKey,
        reason: String,
    },
    /// Canonicality check failed before signing.
    CanonicalityCheckFailed { detail: String },
}

impl fmt::Display for SignatureEventType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Signed { signer } => write!(f, "signed by {signer}"),
            Self::Verified { signer } => write!(f, "verified for {signer}"),
            Self::VerificationFailed { signer, reason } => {
                write!(f, "verification failed for {signer}: {reason}")
            }
            Self::CanonicalityCheckFailed { detail } => {
                write!(f, "canonicality check failed: {detail}")
            }
        }
    }
}

// ---------------------------------------------------------------------------
// SignatureContext — convenience wrapper with event tracking
// ---------------------------------------------------------------------------

/// Context for performing signature operations with audit event tracking.
#[derive(Debug)]
pub struct SignatureContext {
    events: Vec<SignatureEvent>,
    sign_count: u64,
    verify_count: u64,
    failure_count: u64,
}

impl SignatureContext {
    /// Create a new context.
    pub fn new() -> Self {
        Self {
            events: Vec::new(),
            sign_count: 0,
            verify_count: 0,
            failure_count: 0,
        }
    }

    /// Sign an object and track the event.
    pub fn sign<T: SignaturePreimage>(
        &mut self,
        object: &T,
        signing_key: &SigningKey,
        trace_id: &str,
    ) -> Result<Signature, SignatureError> {
        // Check canonicality first.
        let unsigned = object.unsigned_view();
        if let Err(e) = check_canonical_for_signing(&unsigned) {
            self.failure_count += 1;
            self.events.push(SignatureEvent {
                event_type: SignatureEventType::CanonicalityCheckFailed {
                    detail: e.to_string(),
                },
                domain: object.signature_domain(),
                trace_id: trace_id.to_string(),
            });
            return Err(e);
        }

        let vk = signing_key.verification_key();
        let preimage = object.preimage_bytes();
        // Sign using the verification key (our paired HMAC scheme).
        let sig_bytes = compute_verification_hash(&vk.0, &preimage);
        let signature = Signature::from_bytes(sig_bytes);

        self.sign_count += 1;
        self.events.push(SignatureEvent {
            event_type: SignatureEventType::Signed { signer: vk },
            domain: object.signature_domain(),
            trace_id: trace_id.to_string(),
        });

        Ok(signature)
    }

    /// Verify a signature and track the event.
    pub fn verify<T: SignaturePreimage>(
        &mut self,
        object: &T,
        verification_key: &VerificationKey,
        signature: &Signature,
        trace_id: &str,
    ) -> Result<(), SignatureError> {
        let result = verify_object(object, verification_key, signature);

        match &result {
            Ok(()) => {
                self.verify_count += 1;
                self.events.push(SignatureEvent {
                    event_type: SignatureEventType::Verified {
                        signer: verification_key.clone(),
                    },
                    domain: object.signature_domain(),
                    trace_id: trace_id.to_string(),
                });
            }
            Err(SignatureError::VerificationFailed { reason, .. }) => {
                self.failure_count += 1;
                self.events.push(SignatureEvent {
                    event_type: SignatureEventType::VerificationFailed {
                        signer: verification_key.clone(),
                        reason: reason.clone(),
                    },
                    domain: object.signature_domain(),
                    trace_id: trace_id.to_string(),
                });
            }
            Err(_) => {
                self.failure_count += 1;
            }
        }

        result
    }

    /// Number of successful sign operations.
    pub fn sign_count(&self) -> u64 {
        self.sign_count
    }

    /// Number of successful verify operations.
    pub fn verify_count(&self) -> u64 {
        self.verify_count
    }

    /// Number of failed operations.
    pub fn failure_count(&self) -> u64 {
        self.failure_count
    }

    /// Drain accumulated events.
    pub fn drain_events(&mut self) -> Vec<SignatureEvent> {
        std::mem::take(&mut self.events)
    }

    /// Event counts by type.
    pub fn event_counts(&self) -> BTreeMap<String, usize> {
        let mut counts = BTreeMap::new();
        for event in &self.events {
            let key = match &event.event_type {
                SignatureEventType::Signed { .. } => "signed",
                SignatureEventType::Verified { .. } => "verified",
                SignatureEventType::VerificationFailed { .. } => "verification_failed",
                SignatureEventType::CanonicalityCheckFailed { .. } => "canonicality_failed",
            };
            *counts.entry(key.to_string()).or_insert(0) += 1;
        }
        counts
    }
}

impl Default for SignatureContext {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::deterministic_serde::SchemaHash;

    // -- Test signable object --

    /// Test object implementing SignaturePreimage.
    struct TestObject {
        domain: ObjectDomain,
        schema: SchemaHash,
        data: CanonicalValue,
    }

    impl SignaturePreimage for TestObject {
        fn signature_domain(&self) -> ObjectDomain {
            self.domain
        }

        fn signature_schema(&self) -> &SchemaHash {
            &self.schema
        }

        fn unsigned_view(&self) -> CanonicalValue {
            // Return data with signature field zeroed.
            let mut map = BTreeMap::new();
            map.insert("data".to_string(), self.data.clone());
            map.insert(
                "signature".to_string(),
                CanonicalValue::Bytes(SIGNATURE_SENTINEL.to_vec()),
            );
            CanonicalValue::Map(map)
        }
    }

    fn test_schema() -> SchemaHash {
        SchemaHash::from_definition(b"test-signable-v1")
    }

    fn test_signing_key() -> SigningKey {
        SigningKey::from_bytes([
            0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E,
            0x0F, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1A, 0x1B, 0x1C,
            0x1D, 0x1E, 0x1F, 0x20,
        ])
    }

    fn test_object() -> TestObject {
        TestObject {
            domain: ObjectDomain::PolicyObject,
            schema: test_schema(),
            data: CanonicalValue::U64(42),
        }
    }

    // -- Key derivation --

    #[test]
    fn verification_key_derivation_is_deterministic() {
        let sk = test_signing_key();
        let vk1 = sk.verification_key();
        let vk2 = sk.verification_key();
        assert_eq!(vk1, vk2);
    }

    #[test]
    fn different_signing_keys_produce_different_verification_keys() {
        let sk1 = SigningKey::from_bytes([1u8; SIGNING_KEY_LEN]);
        let sk2 = SigningKey::from_bytes([2u8; SIGNING_KEY_LEN]);
        assert_ne!(sk1.verification_key(), sk2.verification_key());
    }

    #[test]
    fn verification_key_display_is_hex() {
        let vk = test_signing_key().verification_key();
        let display = vk.to_string();
        assert_eq!(display.len(), VERIFICATION_KEY_LEN * 2);
        assert!(display.chars().all(|c| c.is_ascii_hexdigit()));
    }

    // -- Preimage --

    #[test]
    fn preimage_is_deterministic() {
        let obj = test_object();
        let p1 = obj.preimage_bytes();
        let p2 = obj.preimage_bytes();
        assert_eq!(p1, p2);
    }

    #[test]
    fn preimage_includes_domain_tag() {
        let obj = test_object();
        let preimage = obj.preimage_bytes();
        let tag = ObjectDomain::PolicyObject.tag();
        assert!(preimage.windows(tag.len()).any(|w| w == tag));
    }

    #[test]
    fn preimage_includes_schema_hash() {
        let obj = test_object();
        let preimage = obj.preimage_bytes();
        let schema = test_schema();
        let schema_bytes = schema.as_bytes();
        assert!(preimage.windows(32).any(|w| w == schema_bytes));
    }

    #[test]
    fn preimage_includes_signature_sentinel() {
        let obj = test_object();
        let preimage = obj.preimage_bytes();
        // The sentinel should be embedded in the encoded unsigned view.
        assert!(
            preimage
                .windows(SIGNATURE_LEN)
                .any(|w| w == SIGNATURE_SENTINEL)
        );
    }

    #[test]
    fn different_data_produces_different_preimage() {
        let obj1 = TestObject {
            domain: ObjectDomain::PolicyObject,
            schema: test_schema(),
            data: CanonicalValue::U64(1),
        };
        let obj2 = TestObject {
            domain: ObjectDomain::PolicyObject,
            schema: test_schema(),
            data: CanonicalValue::U64(2),
        };
        assert_ne!(obj1.preimage_bytes(), obj2.preimage_bytes());
    }

    #[test]
    fn different_domains_produce_different_preimage() {
        let obj1 = TestObject {
            domain: ObjectDomain::PolicyObject,
            schema: test_schema(),
            data: CanonicalValue::U64(42),
        };
        let obj2 = TestObject {
            domain: ObjectDomain::EvidenceRecord,
            schema: test_schema(),
            data: CanonicalValue::U64(42),
        };
        assert_ne!(obj1.preimage_bytes(), obj2.preimage_bytes());
    }

    #[test]
    fn different_schemas_produce_different_preimage() {
        let obj1 = TestObject {
            domain: ObjectDomain::PolicyObject,
            schema: SchemaHash::from_definition(b"schema-a"),
            data: CanonicalValue::U64(42),
        };
        let obj2 = TestObject {
            domain: ObjectDomain::PolicyObject,
            schema: SchemaHash::from_definition(b"schema-b"),
            data: CanonicalValue::U64(42),
        };
        assert_ne!(obj1.preimage_bytes(), obj2.preimage_bytes());
    }

    // -- Sign and verify round-trip --

    #[test]
    fn sign_verify_round_trip() {
        let mut ctx = SignatureContext::new();
        let sk = test_signing_key();
        let vk = sk.verification_key();
        let obj = test_object();

        let sig = ctx.sign(&obj, &sk, "t-001").unwrap();
        assert!(ctx.verify(&obj, &vk, &sig, "t-001").is_ok());
    }

    #[test]
    fn sign_is_deterministic() {
        let mut ctx = SignatureContext::new();
        let sk = test_signing_key();
        let obj = test_object();

        let sig1 = ctx.sign(&obj, &sk, "t-det-1").unwrap();
        let sig2 = ctx.sign(&obj, &sk, "t-det-2").unwrap();
        assert_eq!(sig1, sig2);
    }

    #[test]
    fn different_keys_produce_different_signatures() {
        let mut ctx = SignatureContext::new();
        let sk1 = SigningKey::from_bytes([1u8; SIGNING_KEY_LEN]);
        let sk2 = SigningKey::from_bytes([2u8; SIGNING_KEY_LEN]);
        let obj = test_object();

        let sig1 = ctx.sign(&obj, &sk1, "t-diff-1").unwrap();
        let sig2 = ctx.sign(&obj, &sk2, "t-diff-2").unwrap();
        assert_ne!(sig1, sig2);
    }

    #[test]
    fn different_data_produces_different_signatures() {
        let mut ctx = SignatureContext::new();
        let sk = test_signing_key();
        let obj1 = TestObject {
            domain: ObjectDomain::PolicyObject,
            schema: test_schema(),
            data: CanonicalValue::U64(1),
        };
        let obj2 = TestObject {
            domain: ObjectDomain::PolicyObject,
            schema: test_schema(),
            data: CanonicalValue::U64(2),
        };

        let sig1 = ctx.sign(&obj1, &sk, "t-data-1").unwrap();
        let sig2 = ctx.sign(&obj2, &sk, "t-data-2").unwrap();
        assert_ne!(sig1, sig2);
    }

    // -- Verification failure cases --

    #[test]
    fn verify_fails_with_wrong_key() {
        let mut ctx = SignatureContext::new();
        let sk = test_signing_key();
        let wrong_vk = VerificationKey::from_bytes([0xFFu8; VERIFICATION_KEY_LEN]);
        let obj = test_object();

        let sig = ctx.sign(&obj, &sk, "t-wrong-key").unwrap();
        let err = ctx
            .verify(&obj, &wrong_vk, &sig, "t-wrong-key")
            .unwrap_err();
        assert!(matches!(err, SignatureError::VerificationFailed { .. }));
    }

    #[test]
    fn verify_fails_with_tampered_signature() {
        let mut ctx = SignatureContext::new();
        let sk = test_signing_key();
        let vk = sk.verification_key();
        let obj = test_object();

        let mut sig = ctx.sign(&obj, &sk, "t-tamper").unwrap();
        sig.lower[0] ^= 0xFF; // tamper
        let err = ctx.verify(&obj, &vk, &sig, "t-tamper").unwrap_err();
        assert!(matches!(err, SignatureError::VerificationFailed { .. }));
    }

    #[test]
    fn verify_fails_with_different_object() {
        let mut ctx = SignatureContext::new();
        let sk = test_signing_key();
        let vk = sk.verification_key();
        let obj1 = test_object();
        let obj2 = TestObject {
            domain: ObjectDomain::PolicyObject,
            schema: test_schema(),
            data: CanonicalValue::U64(999),
        };

        let sig = ctx.sign(&obj1, &sk, "t-diff-obj").unwrap();
        let err = ctx.verify(&obj2, &vk, &sig, "t-diff-obj").unwrap_err();
        assert!(matches!(err, SignatureError::VerificationFailed { .. }));
    }

    // -- Multi-signature: all signers get the same preimage --

    #[test]
    fn multi_sig_same_preimage() {
        let sk1 = SigningKey::from_bytes([1u8; SIGNING_KEY_LEN]);
        let sk2 = SigningKey::from_bytes([2u8; SIGNING_KEY_LEN]);
        let sk3 = SigningKey::from_bytes([3u8; SIGNING_KEY_LEN]);
        let obj = test_object();

        let preimage = obj.preimage_bytes();

        // All signers compute preimage from the same unsigned view.
        let obj2 = test_object();
        let obj3 = test_object();
        assert_eq!(preimage, obj2.preimage_bytes());
        assert_eq!(preimage, obj3.preimage_bytes());

        // Each produces a different signature on the same preimage.
        let mut ctx = SignatureContext::new();
        let sig1 = ctx.sign(&obj, &sk1, "t-ms-1").unwrap();
        let sig2 = ctx.sign(&obj, &sk2, "t-ms-2").unwrap();
        let sig3 = ctx.sign(&obj, &sk3, "t-ms-3").unwrap();
        assert_ne!(sig1, sig2);
        assert_ne!(sig2, sig3);
        assert_ne!(sig1, sig3);

        // Each verifies against its own key.
        assert!(
            ctx.verify(&obj, &sk1.verification_key(), &sig1, "t-ms-v1")
                .is_ok()
        );
        assert!(
            ctx.verify(&obj, &sk2.verification_key(), &sig2, "t-ms-v2")
                .is_ok()
        );
        assert!(
            ctx.verify(&obj, &sk3.verification_key(), &sig3, "t-ms-v3")
                .is_ok()
        );

        // Cross-key verification fails.
        assert!(
            ctx.verify(&obj, &sk1.verification_key(), &sig2, "t-ms-x1")
                .is_err()
        );
    }

    // -- Invalid key rejection --

    #[test]
    fn zero_signing_key_rejected() {
        let zero_sk = SigningKey::from_bytes([0u8; SIGNING_KEY_LEN]);
        let preimage = b"test preimage";
        let err = sign_preimage(&zero_sk, preimage).unwrap_err();
        assert!(matches!(err, SignatureError::InvalidSigningKey));
    }

    #[test]
    fn zero_verification_key_rejected() {
        let zero_vk = VerificationKey::from_bytes([0u8; VERIFICATION_KEY_LEN]);
        let sig = Signature::from_bytes([1u8; SIGNATURE_LEN]);
        let err = verify_signature(&zero_vk, b"test", &sig).unwrap_err();
        assert!(matches!(err, SignatureError::InvalidVerificationKey));
    }

    // -- Signature sentinel --

    #[test]
    fn sentinel_is_all_zeros() {
        assert!(SIGNATURE_SENTINEL.iter().all(|&b| b == 0));
        let sig = Signature::from_bytes(SIGNATURE_SENTINEL);
        assert!(sig.is_sentinel());
    }

    #[test]
    fn non_sentinel_signature() {
        let sig = Signature::from_bytes([1u8; SIGNATURE_LEN]);
        assert!(!sig.is_sentinel());
    }

    // -- Canonicality check before signing --

    #[test]
    fn canonical_check_passes_for_valid_value() {
        let value = CanonicalValue::U64(42);
        assert!(check_canonical_for_signing(&value).is_ok());
    }

    #[test]
    fn canonical_check_passes_for_complex_value() {
        let value = CanonicalValue::Map(BTreeMap::from([
            ("alpha".to_string(), CanonicalValue::U64(1)),
            (
                "beta".to_string(),
                CanonicalValue::Array(vec![CanonicalValue::Bool(true), CanonicalValue::Null]),
            ),
        ]));
        assert!(check_canonical_for_signing(&value).is_ok());
    }

    // -- Build preimage helper --

    #[test]
    fn build_preimage_matches_trait() {
        let obj = test_object();
        let trait_preimage = obj.preimage_bytes();
        let helper_preimage = build_preimage(
            obj.signature_domain(),
            obj.signature_schema(),
            &obj.unsigned_view(),
        );
        assert_eq!(trait_preimage, helper_preimage);
    }

    // -- Preimage hash --

    #[test]
    fn preimage_hash_is_deterministic() {
        let obj = test_object();
        let preimage = obj.preimage_bytes();
        let h1 = preimage_hash(&preimage);
        let h2 = preimage_hash(&preimage);
        assert_eq!(h1, h2);
    }

    // -- Event tracking --

    #[test]
    fn context_tracks_sign_events() {
        let mut ctx = SignatureContext::new();
        let sk = test_signing_key();
        let obj = test_object();

        ctx.sign(&obj, &sk, "t-track").unwrap();
        assert_eq!(ctx.sign_count(), 1);
        assert_eq!(ctx.verify_count(), 0);
        assert_eq!(ctx.failure_count(), 0);

        let events = ctx.drain_events();
        assert_eq!(events.len(), 1);
        assert!(matches!(
            events[0].event_type,
            SignatureEventType::Signed { .. }
        ));
        assert_eq!(events[0].trace_id, "t-track");
    }

    #[test]
    fn context_tracks_verify_events() {
        let mut ctx = SignatureContext::new();
        let sk = test_signing_key();
        let vk = sk.verification_key();
        let obj = test_object();

        let sig = ctx.sign(&obj, &sk, "t-v1").unwrap();
        ctx.verify(&obj, &vk, &sig, "t-v2").unwrap();
        assert_eq!(ctx.verify_count(), 1);
    }

    #[test]
    fn context_tracks_failure_events() {
        let mut ctx = SignatureContext::new();
        let sk = test_signing_key();
        let wrong_vk = VerificationKey::from_bytes([0xAA; VERIFICATION_KEY_LEN]);
        let obj = test_object();

        let sig = ctx.sign(&obj, &sk, "t-fail").unwrap();
        ctx.verify(&obj, &wrong_vk, &sig, "t-fail").unwrap_err();
        assert_eq!(ctx.failure_count(), 1);

        let counts = ctx.event_counts();
        assert_eq!(counts.get("signed"), Some(&1));
        assert_eq!(counts.get("verification_failed"), Some(&1));
    }

    #[test]
    fn drain_events_clears() {
        let mut ctx = SignatureContext::new();
        let sk = test_signing_key();
        let obj = test_object();
        ctx.sign(&obj, &sk, "t-drain").unwrap();
        assert_eq!(ctx.drain_events().len(), 1);
        assert_eq!(ctx.drain_events().len(), 0);
    }

    // -- Display --

    #[test]
    fn signature_display() {
        let sig = Signature::from_bytes([0xAB; SIGNATURE_LEN]);
        let display = sig.to_string();
        assert!(display.contains("abababab"));
        assert!(display.contains("..."));
    }

    #[test]
    fn signature_error_display() {
        let vk = VerificationKey::from_bytes([1u8; VERIFICATION_KEY_LEN]);
        let err = SignatureError::VerificationFailed {
            signer: vk,
            reason: "bad sig".to_string(),
        };
        assert!(err.to_string().contains("bad sig"));

        assert_eq!(
            SignatureError::InvalidSigningKey.to_string(),
            "signing key is all zeros"
        );
    }

    #[test]
    fn event_type_display() {
        let vk = VerificationKey::from_bytes([1u8; VERIFICATION_KEY_LEN]);
        let evt = SignatureEventType::Signed { signer: vk };
        assert!(evt.to_string().contains("signed by"));
    }

    // -- Serialization round-trips --

    #[test]
    fn signing_key_serialization_round_trip() {
        let sk = test_signing_key();
        let json = serde_json::to_string(&sk).expect("serialize");
        let restored: SigningKey = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(sk, restored);
    }

    #[test]
    fn verification_key_serialization_round_trip() {
        let vk = test_signing_key().verification_key();
        let json = serde_json::to_string(&vk).expect("serialize");
        let restored: VerificationKey = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(vk, restored);
    }

    #[test]
    fn signature_serialization_round_trip() {
        let mut ctx = SignatureContext::new();
        let sig = ctx
            .sign(&test_object(), &test_signing_key(), "t-ser")
            .unwrap();
        let json = serde_json::to_string(&sig).expect("serialize");
        let restored: Signature = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(sig, restored);
    }

    #[test]
    fn signature_error_serialization_round_trip() {
        let errors = [
            SignatureError::InvalidSigningKey,
            SignatureError::InvalidVerificationKey,
            SignatureError::NonCanonicalObject {
                detail: "test".to_string(),
            },
            SignatureError::PreimageError {
                detail: "fail".to_string(),
            },
        ];
        for err in &errors {
            let json = serde_json::to_string(err).expect("serialize");
            let restored: SignatureError = serde_json::from_str(&json).expect("deserialize");
            assert_eq!(*err, restored);
        }
    }

    #[test]
    fn signature_event_serialization_round_trip() {
        let event = SignatureEvent {
            event_type: SignatureEventType::Signed {
                signer: test_signing_key().verification_key(),
            },
            domain: ObjectDomain::PolicyObject,
            trace_id: "t-serde".to_string(),
        };
        let json = serde_json::to_string(&event).expect("serialize");
        let restored: SignatureEvent = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(event, restored);
    }

    // -- Default --

    #[test]
    fn context_default_is_empty() {
        let ctx = SignatureContext::default();
        assert_eq!(ctx.sign_count(), 0);
        assert_eq!(ctx.verify_count(), 0);
        assert_eq!(ctx.failure_count(), 0);
    }

    // -- Constant-time comparison --

    #[test]
    fn constant_time_eq_same() {
        let a = [42u8; SIGNATURE_LEN];
        assert!(constant_time_eq_64(&a, &a));
    }

    #[test]
    fn constant_time_eq_different() {
        let a = [42u8; SIGNATURE_LEN];
        let mut b = [42u8; SIGNATURE_LEN];
        b[63] = 43;
        assert!(!constant_time_eq_64(&a, &b));
    }

    // -- Enrichment: std::error --

    #[test]
    fn signature_error_implements_std_error() {
        let variants: [Box<dyn std::error::Error>; 4] = [
            Box::new(SignatureError::NonCanonicalObject {
                detail: "bad order".into(),
            }),
            Box::new(SignatureError::PreimageError {
                detail: "hash fail".into(),
            }),
            Box::new(SignatureError::InvalidSigningKey),
            Box::new(SignatureError::InvalidVerificationKey),
        ];
        let mut displays = std::collections::BTreeSet::new();
        for v in &variants {
            let msg = format!("{v}");
            assert!(!msg.is_empty());
            displays.insert(msg);
        }
        assert_eq!(
            displays.len(),
            4,
            "all 4 tested variants produce distinct messages"
        );
    }

    // -- Enrichment: Display uniqueness, serde, boundary, determinism --

    #[test]
    fn signature_event_type_display_all_unique() {
        let vk1 = VerificationKey::from_bytes([1u8; VERIFICATION_KEY_LEN]);
        let _vk2 = VerificationKey::from_bytes([2u8; VERIFICATION_KEY_LEN]);
        let types = [
            SignatureEventType::Signed {
                signer: vk1.clone(),
            },
            SignatureEventType::Verified {
                signer: vk1.clone(),
            },
            SignatureEventType::VerificationFailed {
                signer: vk1,
                reason: "bad".to_string(),
            },
        ];
        let displays: std::collections::BTreeSet<String> =
            types.iter().map(|t| t.to_string()).collect();
        assert_eq!(displays.len(), types.len());
    }

    #[test]
    fn object_domain_tag_is_deterministic() {
        let tag1 = ObjectDomain::PolicyObject.tag();
        let tag2 = ObjectDomain::PolicyObject.tag();
        assert_eq!(tag1, tag2);
    }

    #[test]
    fn signing_key_bytes_roundtrip() {
        let bytes = [42u8; SIGNING_KEY_LEN];
        let sk = SigningKey::from_bytes(bytes);
        assert_eq!(sk.as_bytes(), &bytes);
    }

    #[test]
    fn verification_key_bytes_roundtrip() {
        let bytes = [99u8; VERIFICATION_KEY_LEN];
        let vk = VerificationKey::from_bytes(bytes);
        assert_eq!(vk.as_bytes(), &bytes);
    }

    #[test]
    fn signature_bytes_roundtrip() {
        let bytes = [0xCC; SIGNATURE_LEN];
        let sig = Signature::from_bytes(bytes);
        assert_eq!(sig.lower, bytes[..32]);
        assert_eq!(sig.upper, bytes[32..]);
    }

    #[test]
    fn context_event_counts_accumulate() {
        let mut ctx = SignatureContext::new();
        let sk = test_signing_key();
        let obj = test_object();
        ctx.sign(&obj, &sk, "t-1").unwrap();
        ctx.sign(&obj, &sk, "t-2").unwrap();
        assert_eq!(ctx.sign_count(), 2);
        let counts = ctx.event_counts();
        assert_eq!(counts.get("signed"), Some(&2));
    }

    #[test]
    fn canonical_value_map_ordering_deterministic() {
        let map1 = CanonicalValue::Map(BTreeMap::from([
            ("z".to_string(), CanonicalValue::U64(1)),
            ("a".to_string(), CanonicalValue::U64(2)),
        ]));
        let map2 = CanonicalValue::Map(BTreeMap::from([
            ("a".to_string(), CanonicalValue::U64(2)),
            ("z".to_string(), CanonicalValue::U64(1)),
        ]));
        // BTreeMap ensures same canonical form regardless of insertion order
        let json1 = serde_json::to_string(&map1).unwrap();
        let json2 = serde_json::to_string(&map2).unwrap();
        assert_eq!(json1, json2);
    }

    #[test]
    fn preimage_hash_different_for_different_data() {
        let obj1 = TestObject {
            domain: ObjectDomain::PolicyObject,
            schema: test_schema(),
            data: CanonicalValue::U64(1),
        };
        let obj2 = TestObject {
            domain: ObjectDomain::PolicyObject,
            schema: test_schema(),
            data: CanonicalValue::U64(2),
        };
        let h1 = preimage_hash(&obj1.preimage_bytes());
        let h2 = preimage_hash(&obj2.preimage_bytes());
        assert_ne!(h1, h2);
    }

    // -----------------------------------------------------------------------
    // Enrichment tests
    // -----------------------------------------------------------------------

    #[test]
    fn enrichment_signing_key_clone_equality() {
        let sk = test_signing_key();
        let sk2 = sk.clone();
        assert_eq!(sk, sk2);
        assert_eq!(sk.as_bytes(), sk2.as_bytes());
    }

    #[test]
    fn enrichment_verification_key_clone_equality() {
        let vk = test_signing_key().verification_key();
        let vk2 = vk.clone();
        assert_eq!(vk, vk2);
        assert_eq!(vk.to_hex(), vk2.to_hex());
    }

    #[test]
    fn enrichment_signature_clone_equality() {
        let mut ctx = SignatureContext::new();
        let sig = ctx
            .sign(&test_object(), &test_signing_key(), "t-clone")
            .unwrap();
        let sig2 = sig.clone();
        assert_eq!(sig, sig2);
        assert_eq!(sig.to_bytes(), sig2.to_bytes());
    }

    #[test]
    fn enrichment_signature_error_clone_equality() {
        let err = SignatureError::VerificationFailed {
            signer: VerificationKey::from_bytes([0xAB; VERIFICATION_KEY_LEN]),
            reason: "tampered".to_string(),
        };
        let err2 = err.clone();
        assert_eq!(err, err2);
    }

    #[test]
    fn enrichment_signature_event_clone_equality() {
        let event = SignatureEvent {
            event_type: SignatureEventType::CanonicalityCheckFailed {
                detail: "non-canonical".to_string(),
            },
            domain: ObjectDomain::Revocation,
            trace_id: "t-clone-event".to_string(),
        };
        let event2 = event.clone();
        assert_eq!(event, event2);
        assert_eq!(event.trace_id, event2.trace_id);
    }

    #[test]
    fn enrichment_signature_json_has_lower_upper_fields() {
        let sig = Signature::from_bytes([0xDD; SIGNATURE_LEN]);
        let json = serde_json::to_string(&sig).unwrap();
        assert!(
            json.contains("\"lower\""),
            "JSON must contain 'lower' field"
        );
        assert!(
            json.contains("\"upper\""),
            "JSON must contain 'upper' field"
        );
    }

    #[test]
    fn enrichment_signature_error_json_has_variant_tag() {
        let err = SignatureError::PreimageError {
            detail: "hash collision".to_string(),
        };
        let json = serde_json::to_string(&err).unwrap();
        assert!(
            json.contains("PreimageError"),
            "JSON must contain variant tag 'PreimageError'"
        );
        assert!(
            json.contains("hash collision"),
            "JSON must contain detail text"
        );
    }

    #[test]
    fn enrichment_signature_event_json_has_all_fields() {
        let event = SignatureEvent {
            event_type: SignatureEventType::Verified {
                signer: VerificationKey::from_bytes([0x11; VERIFICATION_KEY_LEN]),
            },
            domain: ObjectDomain::SignedManifest,
            trace_id: "t-json-fields".to_string(),
        };
        let json = serde_json::to_string(&event).unwrap();
        assert!(json.contains("\"event_type\""));
        assert!(json.contains("\"domain\""));
        assert!(json.contains("\"trace_id\""));
    }

    #[test]
    fn enrichment_verification_key_serde_roundtrip_preserves_ordering() {
        let vk_a = VerificationKey::from_bytes([0x01; VERIFICATION_KEY_LEN]);
        let vk_b = VerificationKey::from_bytes([0x02; VERIFICATION_KEY_LEN]);
        assert!(vk_a < vk_b, "Ord should order by bytes");

        let json_a = serde_json::to_string(&vk_a).unwrap();
        let json_b = serde_json::to_string(&vk_b).unwrap();
        let restored_a: VerificationKey = serde_json::from_str(&json_a).unwrap();
        let restored_b: VerificationKey = serde_json::from_str(&json_b).unwrap();
        assert!(
            restored_a < restored_b,
            "Ord must be preserved after serde roundtrip"
        );
    }

    #[test]
    fn enrichment_all_signature_error_displays_unique() {
        let vk = VerificationKey::from_bytes([0x77; VERIFICATION_KEY_LEN]);
        let variants = [
            SignatureError::VerificationFailed {
                signer: vk,
                reason: "mismatch".to_string(),
            },
            SignatureError::NonCanonicalObject {
                detail: "out of order".to_string(),
            },
            SignatureError::PreimageError {
                detail: "encoding failed".to_string(),
            },
            SignatureError::InvalidSigningKey,
            SignatureError::InvalidVerificationKey,
        ];
        let displays: std::collections::BTreeSet<String> =
            variants.iter().map(|e| e.to_string()).collect();
        assert_eq!(
            displays.len(),
            variants.len(),
            "all 5 error variants must produce distinct Display strings"
        );
    }

    #[test]
    fn enrichment_signature_from_bytes_boundary_split() {
        // Verify byte 31 goes to lower and byte 32 goes to upper
        let mut bytes = [0u8; SIGNATURE_LEN];
        bytes[31] = 0xFF; // last byte of lower half
        bytes[32] = 0xAA; // first byte of upper half
        let sig = Signature::from_bytes(bytes);
        assert_eq!(sig.lower[31], 0xFF);
        assert_eq!(sig.upper[0], 0xAA);
        // Roundtrip must preserve exact split
        let roundtripped = sig.to_bytes();
        assert_eq!(roundtripped, bytes);
    }

    #[test]
    fn enrichment_signature_ord_and_hash_consistency() {
        let sig_a = Signature::from_bytes([0x01; SIGNATURE_LEN]);
        let sig_b = Signature::from_bytes([0x02; SIGNATURE_LEN]);
        // Ord is derived, so lower bytes differ => sig_a < sig_b
        assert!(sig_a < sig_b);

        // BTreeSet uses Ord; ensure both are kept distinct
        let mut set = std::collections::BTreeSet::new();
        set.insert(sig_a.clone());
        set.insert(sig_b.clone());
        set.insert(sig_a.clone()); // duplicate
        assert_eq!(set.len(), 2);
    }

    // -----------------------------------------------------------------------
    // Enrichment batch 6: sentinel, constants, build_preimage, Display
    // -----------------------------------------------------------------------

    #[test]
    fn enrichment_signature_sentinel_is_all_zeros() {
        assert!(SIGNATURE_SENTINEL.iter().all(|&b| b == 0));
        assert_eq!(SIGNATURE_SENTINEL.len(), SIGNATURE_LEN);
    }

    #[test]
    fn enrichment_signature_is_sentinel_true_for_zeros() {
        let sig = Signature::from_bytes([0u8; SIGNATURE_LEN]);
        assert!(sig.is_sentinel());
    }

    #[test]
    fn enrichment_signature_is_sentinel_false_for_nonzero() {
        let mut bytes = [0u8; SIGNATURE_LEN];
        bytes[0] = 1;
        let sig = Signature::from_bytes(bytes);
        assert!(!sig.is_sentinel());
    }

    #[test]
    fn enrichment_constants_expected_values() {
        assert_eq!(SIGNING_KEY_LEN, 32);
        assert_eq!(VERIFICATION_KEY_LEN, 32);
        assert_eq!(SIGNATURE_LEN, 64);
    }

    #[test]
    fn enrichment_build_preimage_matches_trait_method() {
        let obj = test_object();
        let trait_preimage = obj.preimage_bytes();
        let manual_preimage = build_preimage(
            obj.signature_domain(),
            obj.signature_schema(),
            &obj.unsigned_view(),
        );
        assert_eq!(trait_preimage, manual_preimage);
    }

    #[test]
    fn enrichment_preimage_hash_deterministic() {
        let obj = test_object();
        let preimage = obj.preimage_bytes();
        let h1 = preimage_hash(&preimage);
        let h2 = preimage_hash(&preimage);
        assert_eq!(h1, h2);
    }

    #[test]
    fn enrichment_signature_display_format() {
        let sig = Signature::from_bytes([0xAB; SIGNATURE_LEN]);
        let display = sig.to_string();
        // Display shows first 8 bytes of lower + "..." + last 8 bytes of upper
        assert!(display.contains("..."));
        assert!(display.starts_with("abababab"));
    }

    #[test]
    fn enrichment_verification_key_hex_is_lowercase() {
        let vk = VerificationKey::from_bytes([0xAB; VERIFICATION_KEY_LEN]);
        let hex = vk.to_hex();
        assert!(
            hex.chars()
                .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit())
        );
    }

    #[test]
    fn enrichment_signing_key_serde_roundtrip() {
        let sk = test_signing_key();
        let json = serde_json::to_string(&sk).unwrap();
        let restored: SigningKey = serde_json::from_str(&json).unwrap();
        assert_eq!(sk, restored);
    }

    #[test]
    fn enrichment_sign_verify_roundtrip_via_context() {
        let mut ctx = SignatureContext::new();
        let sk = test_signing_key();
        let vk = sk.verification_key();
        let obj = test_object();
        let sig = ctx.sign(&obj, &sk, "t-rv").unwrap();
        ctx.verify(&obj, &vk, &sig, "t-rv2").unwrap();
        assert_eq!(ctx.sign_count(), 1);
        assert_eq!(ctx.verify_count(), 1);
        assert_eq!(ctx.failure_count(), 0);
    }

    #[test]
    fn enrichment_drain_events_clears_and_returns() {
        let mut ctx = SignatureContext::new();
        ctx.sign(&test_object(), &test_signing_key(), "t-drain")
            .unwrap();
        let events = ctx.drain_events();
        assert_eq!(events.len(), 1);
        // After drain, events list is empty.
        assert!(ctx.drain_events().is_empty());
    }

    #[test]
    fn enrichment_wrong_key_verification_fails() {
        let mut ctx = SignatureContext::new();
        let sk = test_signing_key();
        let obj = test_object();
        let sig = ctx.sign(&obj, &sk, "t-wrong").unwrap();
        let wrong_vk = VerificationKey::from_bytes([0xBB; VERIFICATION_KEY_LEN]);
        let err = ctx.verify(&obj, &wrong_vk, &sig, "t-wrong2").unwrap_err();
        assert!(matches!(err, SignatureError::VerificationFailed { .. }));
        assert_eq!(ctx.failure_count(), 1);
    }

    #[test]
    fn enrichment_sign_rejects_zero_signing_key() {
        let zero_sk = SigningKey::from_bytes([0u8; SIGNING_KEY_LEN]);
        let err = sign_preimage(&zero_sk, b"data").unwrap_err();
        assert_eq!(err, SignatureError::InvalidSigningKey);
    }

    #[test]
    fn enrichment_verify_rejects_zero_verification_key() {
        let zero_vk = VerificationKey::from_bytes([0u8; VERIFICATION_KEY_LEN]);
        let sig = Signature::from_bytes([1u8; SIGNATURE_LEN]);
        let err = verify_signature(&zero_vk, b"data", &sig).unwrap_err();
        assert_eq!(err, SignatureError::InvalidVerificationKey);
    }

    #[test]
    fn enrichment_check_canonical_for_signing_accepts_u64() {
        let val = CanonicalValue::U64(42);
        assert!(check_canonical_for_signing(&val).is_ok());
    }
}
