//! Deterministic, trust-boundary-safe ordering for multi-signature arrays.
//!
//! The core invariant is stronger than "constructors sort": every persisted
//! array must deserialize through the same sorted/unique validation, and quorum
//! verification re-checks the invariant before counting signatures. This keeps
//! crafted persisted JSON from turning one authorized key into multiple quorum
//! votes.
//!
//! Canonical ordering is lexicographic byte ordering of verification keys.
//!
//! Plan references: Section 10.10 item 5, 9E.2 ("Multi-signature vectors
//! must be sorted by stable signer key ordering before verification").

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;

use serde::{Deserialize, Serialize};

use crate::signature_preimage::{Signature, SignatureError, VerificationKey};

/// A single signer's contribution: verification key + signature.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SignerSignature {
    pub signer: VerificationKey,
    pub signature: Signature,
}

impl SignerSignature {
    pub fn new(signer: VerificationKey, signature: Signature) -> Self {
        Self { signer, signature }
    }
}

impl PartialOrd for SignerSignature {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for SignerSignature {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.signer.as_bytes().cmp(other.signer.as_bytes())
    }
}

/// Errors from multi-signature operations.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum MultiSigError {
    UnsortedSignatureArray {
        position: usize,
        prev_key_hex: String,
        current_key_hex: String,
    },
    DuplicateSignerKey {
        key_hex: String,
        positions: (usize, usize),
    },
    QuorumNotMet {
        required: usize,
        valid: usize,
        total: usize,
    },
    EmptyArray,
    ZeroQuorumThreshold,
    ThresholdExceedsSignerCount {
        threshold: usize,
        signer_count: usize,
    },
    SignatureError {
        detail: String,
    },
}

impl fmt::Display for MultiSigError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnsortedSignatureArray {
                position,
                prev_key_hex,
                current_key_hex,
            } => write!(
                f,
                "unsorted at position {position}: {prev_key_hex} >= {current_key_hex}"
            ),
            Self::DuplicateSignerKey { key_hex, positions } => write!(
                f,
                "duplicate signer key {key_hex} at positions {} and {}",
                positions.0, positions.1
            ),
            Self::QuorumNotMet {
                required,
                valid,
                total,
            } => write!(
                f,
                "quorum not met: {valid}/{total} valid, {required} required"
            ),
            Self::EmptyArray => f.write_str("empty signature array"),
            Self::ZeroQuorumThreshold => f.write_str("quorum threshold is zero"),
            Self::ThresholdExceedsSignerCount {
                threshold,
                signer_count,
            } => write!(
                f,
                "threshold {threshold} exceeds signer count {signer_count}"
            ),
            Self::SignatureError { detail } => write!(f, "signature error: {detail}"),
        }
    }
}

impl std::error::Error for MultiSigError {}

/// Signature array with a stable sorted/unique signer invariant.
///
/// `Deserialize` is implemented manually so persisted input cannot bypass the
/// constructor invariant. `verify_quorum` defensively checks the invariant
/// again before any vote is counted.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct SortedSignatureArray {
    entries: Vec<SignerSignature>,
}

impl<'de> Deserialize<'de> for SortedSignatureArray {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        #[derive(Deserialize)]
        struct Wire {
            entries: Vec<SignerSignature>,
        }

        let wire = Wire::deserialize(deserializer)?;
        Self::new(wire.entries).map_err(serde::de::Error::custom)
    }
}

impl SortedSignatureArray {
    pub fn new(entries: Vec<SignerSignature>) -> Result<Self, MultiSigError> {
        if entries.is_empty() {
            return Err(MultiSigError::EmptyArray);
        }
        verify_sorted_no_duplicates(&entries)?;
        Ok(Self { entries })
    }

    pub fn from_unsorted(mut entries: Vec<SignerSignature>) -> Result<Self, MultiSigError> {
        if entries.is_empty() {
            return Err(MultiSigError::EmptyArray);
        }
        entries.sort();
        verify_sorted_no_duplicates(&entries)?;
        Ok(Self { entries })
    }

    pub fn insert(&mut self, entry: SignerSignature) -> Result<(), MultiSigError> {
        match self
            .entries
            .binary_search_by(|existing| existing.signer.as_bytes().cmp(entry.signer.as_bytes()))
        {
            Ok(position) => Err(MultiSigError::DuplicateSignerKey {
                key_hex: entry.signer.to_hex(),
                positions: (position, self.entries.len()),
            }),
            Err(position) => {
                self.entries.insert(position, entry);
                Ok(())
            }
        }
    }

    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    pub fn entries(&self) -> &[SignerSignature] {
        &self.entries
    }

    pub fn signer_keys(&self) -> Vec<&VerificationKey> {
        self.entries.iter().map(|entry| &entry.signer).collect()
    }

    pub fn contains_signer(&self, key: &VerificationKey) -> bool {
        self.entries
            .binary_search_by(|entry| entry.signer.as_bytes().cmp(key.as_bytes()))
            .is_ok()
    }

    /// Verify at least `threshold` distinct authorized signatures.
    ///
    /// The authorized input is treated as a mathematical set for threshold
    /// sizing: duplicate keys in that caller-provided slice do not increase the
    /// maximum possible quorum. The signature array itself must be canonical
    /// and unique before any verification callback runs.
    pub fn verify_quorum<F>(
        &self,
        threshold: usize,
        authorized_signers: &[VerificationKey],
        mut verify_fn: F,
    ) -> Result<QuorumResult, MultiSigError>
    where
        F: FnMut(&VerificationKey, &Signature) -> Result<(), SignatureError>,
    {
        if self.entries.is_empty() {
            return Err(MultiSigError::EmptyArray);
        }
        verify_sorted_no_duplicates(&self.entries)?;
        if threshold == 0 {
            return Err(MultiSigError::ZeroQuorumThreshold);
        }

        let authorized: BTreeSet<&VerificationKey> = authorized_signers.iter().collect();
        if threshold > authorized.len() {
            return Err(MultiSigError::ThresholdExceedsSignerCount {
                threshold,
                signer_count: authorized.len(),
            });
        }

        let mut valid_count = 0usize;
        let mut invalid = Vec::new();
        let mut unauthorized = Vec::new();

        for entry in &self.entries {
            if !authorized.contains(&entry.signer) {
                unauthorized.push(entry.signer.clone());
                continue;
            }
            match verify_fn(&entry.signer, &entry.signature) {
                Ok(()) => valid_count += 1,
                Err(error) => invalid.push((entry.signer.clone(), error.to_string())),
            }
        }

        if valid_count < threshold {
            return Err(MultiSigError::QuorumNotMet {
                required: threshold,
                valid: valid_count,
                total: self.entries.len(),
            });
        }

        Ok(QuorumResult {
            quorum_met: true,
            valid_count,
            invalid_count: invalid.len(),
            unauthorized_count: unauthorized.len(),
            total: self.entries.len(),
            threshold,
            invalid_signers: invalid,
            unauthorized_signers: unauthorized,
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct QuorumResult {
    pub quorum_met: bool,
    pub valid_count: usize,
    pub invalid_count: usize,
    pub unauthorized_count: usize,
    pub total: usize,
    pub threshold: usize,
    pub invalid_signers: Vec<(VerificationKey, String)>,
    pub unauthorized_signers: Vec<VerificationKey>,
}

impl fmt::Display for QuorumResult {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "quorum: {}/{} valid (threshold {}), {} invalid, {} unauthorized",
            self.valid_count,
            self.total,
            self.threshold,
            self.invalid_count,
            self.unauthorized_count
        )
    }
}

fn verify_sorted_no_duplicates(entries: &[SignerSignature]) -> Result<(), MultiSigError> {
    for (index, pair) in entries.windows(2).enumerate() {
        let previous = &pair[0].signer;
        let current = &pair[1].signer;
        match previous.as_bytes().cmp(current.as_bytes()) {
            std::cmp::Ordering::Less => {}
            std::cmp::Ordering::Equal => {
                return Err(MultiSigError::DuplicateSignerKey {
                    key_hex: current.to_hex(),
                    positions: (index, index + 1),
                });
            }
            std::cmp::Ordering::Greater => {
                return Err(MultiSigError::UnsortedSignatureArray {
                    position: index + 1,
                    prev_key_hex: previous.to_hex(),
                    current_key_hex: current.to_hex(),
                });
            }
        }
    }
    Ok(())
}

pub fn is_sorted(entries: &[SignerSignature]) -> Result<(), MultiSigError> {
    if entries.is_empty() {
        return Err(MultiSigError::EmptyArray);
    }
    verify_sorted_no_duplicates(entries)
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MultiSigEvent {
    pub event_type: MultiSigEventType,
    pub trace_id: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum MultiSigEventType {
    ArrayCreated {
        signer_count: usize,
    },
    SignatureInserted {
        signer_hex: String,
    },
    QuorumVerified {
        valid: usize,
        threshold: usize,
        total: usize,
    },
    QuorumFailed {
        valid: usize,
        threshold: usize,
        total: usize,
    },
    SortingViolation {
        detail: String,
    },
    DuplicateSigner {
        key_hex: String,
    },
}

impl fmt::Display for MultiSigEventType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ArrayCreated { signer_count } => {
                write!(f, "array created with {signer_count} signers")
            }
            Self::SignatureInserted { signer_hex } => {
                write!(f, "signature inserted for {signer_hex}")
            }
            Self::QuorumVerified {
                valid,
                threshold,
                total,
            } => write!(
                f,
                "quorum verified: {valid}/{total} (threshold {threshold})"
            ),
            Self::QuorumFailed {
                valid,
                threshold,
                total,
            } => write!(f, "quorum failed: {valid}/{total} (threshold {threshold})"),
            Self::SortingViolation { detail } => write!(f, "sorting violation: {detail}"),
            Self::DuplicateSigner { key_hex } => write!(f, "duplicate signer: {key_hex}"),
        }
    }
}

#[derive(Debug, Default)]
pub struct MultiSigContext {
    events: Vec<MultiSigEvent>,
}

impl MultiSigContext {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn create_sorted(
        &mut self,
        entries: Vec<SignerSignature>,
        trace_id: &str,
    ) -> Result<SortedSignatureArray, MultiSigError> {
        match SortedSignatureArray::from_unsorted(entries) {
            Ok(array) => {
                self.events.push(MultiSigEvent {
                    event_type: MultiSigEventType::ArrayCreated {
                        signer_count: array.len(),
                    },
                    trace_id: trace_id.to_string(),
                });
                Ok(array)
            }
            Err(error) => {
                let event_type = match &error {
                    MultiSigError::DuplicateSignerKey { key_hex, .. } => {
                        MultiSigEventType::DuplicateSigner {
                            key_hex: key_hex.clone(),
                        }
                    }
                    other => MultiSigEventType::SortingViolation {
                        detail: other.to_string(),
                    },
                };
                self.events.push(MultiSigEvent {
                    event_type,
                    trace_id: trace_id.to_string(),
                });
                Err(error)
            }
        }
    }

    pub fn verify_quorum<F>(
        &mut self,
        array: &SortedSignatureArray,
        threshold: usize,
        authorized_signers: &[VerificationKey],
        verify_fn: F,
        trace_id: &str,
    ) -> Result<QuorumResult, MultiSigError>
    where
        F: FnMut(&VerificationKey, &Signature) -> Result<(), SignatureError>,
    {
        match array.verify_quorum(threshold, authorized_signers, verify_fn) {
            Ok(result) => {
                self.events.push(MultiSigEvent {
                    event_type: MultiSigEventType::QuorumVerified {
                        valid: result.valid_count,
                        threshold: result.threshold,
                        total: result.total,
                    },
                    trace_id: trace_id.to_string(),
                });
                Ok(result)
            }
            Err(error) => {
                if let MultiSigError::QuorumNotMet {
                    valid,
                    required,
                    total,
                } = &error
                {
                    self.events.push(MultiSigEvent {
                        event_type: MultiSigEventType::QuorumFailed {
                            valid: *valid,
                            threshold: *required,
                            total: *total,
                        },
                        trace_id: trace_id.to_string(),
                    });
                }
                Err(error)
            }
        }
    }

    pub fn drain_events(&mut self) -> Vec<MultiSigEvent> {
        std::mem::take(&mut self.events)
    }

    pub fn event_counts(&self) -> BTreeMap<String, usize> {
        let mut counts = BTreeMap::new();
        for event in &self.events {
            let key = match &event.event_type {
                MultiSigEventType::ArrayCreated { .. } => "array_created",
                MultiSigEventType::SignatureInserted { .. } => "signature_inserted",
                MultiSigEventType::QuorumVerified { .. } => "quorum_verified",
                MultiSigEventType::QuorumFailed { .. } => "quorum_failed",
                MultiSigEventType::SortingViolation { .. } => "sorting_violation",
                MultiSigEventType::DuplicateSigner { .. } => "duplicate_signer",
            };
            *counts.entry(key.to_string()).or_insert(0) += 1;
        }
        counts
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::deterministic_serde::{CanonicalValue, SchemaHash};
    use crate::engine_object_id::ObjectDomain;
    use crate::signature_preimage::{
        SignatureContext, SignaturePreimage, SigningKey, SIGNATURE_LEN, SIGNATURE_SENTINEL,
        SIGNING_KEY_LEN,
    };

    struct TestObj {
        schema: SchemaHash,
        data: u64,
    }

    impl SignaturePreimage for TestObj {
        fn signature_domain(&self) -> ObjectDomain {
            ObjectDomain::PolicyObject
        }

        fn signature_schema(&self) -> &SchemaHash {
            &self.schema
        }

        fn unsigned_view(&self) -> CanonicalValue {
            let mut map = BTreeMap::new();
            map.insert("data".to_string(), CanonicalValue::U64(self.data));
            map.insert(
                "signature".to_string(),
                CanonicalValue::Bytes(SIGNATURE_SENTINEL.to_vec()),
            );
            CanonicalValue::Map(map)
        }
    }

    fn object() -> TestObj {
        TestObj {
            schema: SchemaHash::from_definition(b"test-multisig-v1"),
            data: 42,
        }
    }

    fn key(seed: u8) -> SigningKey {
        SigningKey::from_bytes([seed; SIGNING_KEY_LEN]).expect("valid test signing key")
    }

    fn signed_entry(seed: u8, object: &TestObj) -> SignerSignature {
        let signing_key = key(seed);
        let mut context = SignatureContext::new();
        let signature = context
            .sign(object, &signing_key, "sorted-multisig-test")
            .expect("sign object");
        SignerSignature::new(signing_key.verification_key(), signature)
    }

    fn verify_real(
        key: &VerificationKey,
        signature: &Signature,
        preimage: &[u8],
    ) -> Result<(), SignatureError> {
        crate::signature_preimage::verify_signature(key, preimage, signature)
    }

    #[test]
    fn sorted_constructor_accepts_canonical_input() {
        let object = object();
        let mut entries = vec![signed_entry(1, &object), signed_entry(2, &object)];
        entries.sort();
        assert_eq!(SortedSignatureArray::new(entries).expect("sorted").len(), 2);
    }

    #[test]
    fn sorted_constructor_rejects_unsorted_input() {
        let object = object();
        let mut entries = vec![signed_entry(1, &object), signed_entry(2, &object)];
        entries.sort();
        entries.reverse();
        assert!(matches!(
            SortedSignatureArray::new(entries),
            Err(MultiSigError::UnsortedSignatureArray { .. })
        ));
    }

    #[test]
    fn from_unsorted_canonicalizes_input() {
        let object = object();
        let entries = vec![signed_entry(3, &object), signed_entry(1, &object), signed_entry(2, &object)];
        let array = SortedSignatureArray::from_unsorted(entries).expect("canonicalize");
        assert!(is_sorted(array.entries()).is_ok());
    }

    #[test]
    fn duplicate_signer_is_rejected_on_construction() {
        let object = object();
        let entry = signed_entry(4, &object);
        assert!(matches!(
            SortedSignatureArray::from_unsorted(vec![entry.clone(), entry]),
            Err(MultiSigError::DuplicateSignerKey { .. })
        ));
    }

    #[test]
    fn empty_array_is_rejected() {
        assert!(matches!(
            SortedSignatureArray::new(Vec::new()),
            Err(MultiSigError::EmptyArray)
        ));
    }

    #[test]
    fn insert_maintains_order() {
        let object = object();
        let mut array = SortedSignatureArray::from_unsorted(vec![
            signed_entry(1, &object),
            signed_entry(3, &object),
        ])
        .expect("array");
        array.insert(signed_entry(2, &object)).expect("insert");
        assert!(is_sorted(array.entries()).is_ok());
        assert_eq!(array.len(), 3);
    }

    #[test]
    fn duplicate_insert_is_rejected() {
        let object = object();
        let entry = signed_entry(5, &object);
        let mut array = SortedSignatureArray::new(vec![entry.clone()]).expect("array");
        assert!(matches!(
            array.insert(entry),
            Err(MultiSigError::DuplicateSignerKey { .. })
        ));
    }

    #[test]
    fn contains_signer_and_signer_keys_are_consistent() {
        let object = object();
        let array = SortedSignatureArray::from_unsorted(vec![
            signed_entry(1, &object),
            signed_entry(2, &object),
        ])
        .expect("array");
        for signer in array.signer_keys() {
            assert!(array.contains_signer(signer));
        }
    }

    #[test]
    fn is_sorted_rejects_empty() {
        assert!(matches!(is_sorted(&[]), Err(MultiSigError::EmptyArray)));
    }

    #[test]
    fn serde_roundtrip_preserves_wire_shape_and_invariant() {
        let object = object();
        let array = SortedSignatureArray::from_unsorted(vec![
            signed_entry(1, &object),
            signed_entry(2, &object),
        ])
        .expect("array");
        let value = serde_json::to_value(&array).expect("serialize");
        assert!(value.get("entries").is_some());
        let restored: SortedSignatureArray = serde_json::from_value(value).expect("deserialize");
        assert_eq!(restored, array);
        assert!(is_sorted(restored.entries()).is_ok());
    }

    #[test]
    fn serde_rejects_duplicate_signer_array() {
        let object = object();
        let entry = signed_entry(6, &object);
        let value = serde_json::json!({"entries": [entry.clone(), entry]});
        let result = serde_json::from_value::<SortedSignatureArray>(value);
        assert!(result.is_err());
    }

    #[test]
    fn serde_rejects_unsorted_signer_array() {
        let object = object();
        let mut entries = vec![signed_entry(1, &object), signed_entry(2, &object)];
        entries.sort();
        entries.reverse();
        let value = serde_json::json!({"entries": entries});
        let result = serde_json::from_value::<SortedSignatureArray>(value);
        assert!(result.is_err());
    }

    #[test]
    fn valid_distinct_quorum_succeeds() {
        let object = object();
        let preimage = object.preimage_bytes();
        let array = SortedSignatureArray::from_unsorted(vec![
            signed_entry(1, &object),
            signed_entry(2, &object),
            signed_entry(3, &object),
        ])
        .expect("array");
        let authorized = array.signer_keys().into_iter().cloned().collect::<Vec<_>>();
        let result = array
            .verify_quorum(2, &authorized, |key, signature| {
                verify_real(key, signature, &preimage)
            })
            .expect("quorum");
        assert_eq!(result.valid_count, 3);
    }

    #[test]
    fn invalid_signature_does_not_count() {
        let object = object();
        let preimage = object.preimage_bytes();
        let first = signed_entry(1, &object);
        let second_key = key(2).verification_key();
        let invalid = SignerSignature::new(
            second_key.clone(),
            Signature::from_bytes([0xAA; SIGNATURE_LEN]),
        );
        let array = SortedSignatureArray::from_unsorted(vec![first.clone(), invalid]).expect("array");
        let result = array.verify_quorum(
            2,
            &[first.signer, second_key],
            |key, signature| verify_real(key, signature, &preimage),
        );
        assert!(matches!(result, Err(MultiSigError::QuorumNotMet { valid: 1, .. })));
    }

    #[test]
    fn unauthorized_signature_does_not_count() {
        let object = object();
        let array = SortedSignatureArray::new(vec![signed_entry(1, &object)]).expect("array");
        let other = key(9).verification_key();
        assert!(matches!(
            array.verify_quorum(1, &[other], |_, _| Ok(())),
            Err(MultiSigError::QuorumNotMet { valid: 0, .. })
        ));
    }

    #[test]
    fn zero_threshold_is_rejected() {
        let object = object();
        let entry = signed_entry(1, &object);
        let signer = entry.signer.clone();
        let array = SortedSignatureArray::new(vec![entry]).expect("array");
        assert!(matches!(
            array.verify_quorum(0, &[signer], |_, _| Ok(())),
            Err(MultiSigError::ZeroQuorumThreshold)
        ));
    }

    #[test]
    fn threshold_exceeding_distinct_authorized_signers_is_rejected() {
        let object = object();
        let entry = signed_entry(1, &object);
        let signer = entry.signer.clone();
        let array = SortedSignatureArray::new(vec![entry]).expect("array");
        assert!(matches!(
            array.verify_quorum(2, &[signer], |_, _| Ok(())),
            Err(MultiSigError::ThresholdExceedsSignerCount {
                threshold: 2,
                signer_count: 1
            })
        ));
    }

    #[test]
    fn duplicate_authorized_keys_cannot_inflate_threshold() {
        let object = object();
        let entry = signed_entry(1, &object);
        let signer = entry.signer.clone();
        let array = SortedSignatureArray::new(vec![entry]).expect("array");
        assert!(matches!(
            array.verify_quorum(2, &[signer.clone(), signer], |_, _| Ok(())),
            Err(MultiSigError::ThresholdExceedsSignerCount {
                threshold: 2,
                signer_count: 1
            })
        ));
    }

    #[test]
    fn verify_quorum_rechecks_duplicate_in_memory_invariant() {
        let object = object();
        let entry = signed_entry(1, &object);
        let signer = entry.signer.clone();
        let malformed = SortedSignatureArray {
            entries: vec![entry.clone(), entry],
        };
        assert!(matches!(
            malformed.verify_quorum(1, &[signer], |_, _| Ok(())),
            Err(MultiSigError::DuplicateSignerKey { .. })
        ));
    }

    #[test]
    fn verify_quorum_rechecks_sorted_in_memory_invariant() {
        let object = object();
        let mut entries = vec![signed_entry(1, &object), signed_entry(2, &object)];
        entries.sort();
        entries.reverse();
        let authorized = entries.iter().map(|entry| entry.signer.clone()).collect::<Vec<_>>();
        let malformed = SortedSignatureArray { entries };
        assert!(matches!(
            malformed.verify_quorum(1, &authorized, |_, _| Ok(())),
            Err(MultiSigError::UnsortedSignatureArray { .. })
        ));
    }

    #[test]
    fn context_tracks_successful_creation() {
        let object = object();
        let mut context = MultiSigContext::new();
        context
            .create_sorted(vec![signed_entry(1, &object)], "create")
            .expect("create");
        assert_eq!(context.event_counts().get("array_created"), Some(&1));
    }

    #[test]
    fn context_tracks_duplicate_creation_failure() {
        let object = object();
        let entry = signed_entry(1, &object);
        let mut context = MultiSigContext::new();
        assert!(context
            .create_sorted(vec![entry.clone(), entry], "duplicate")
            .is_err());
        assert_eq!(context.event_counts().get("duplicate_signer"), Some(&1));
    }

    #[test]
    fn context_tracks_quorum_success() {
        let object = object();
        let preimage = object.preimage_bytes();
        let entry = signed_entry(1, &object);
        let signer = entry.signer.clone();
        let array = SortedSignatureArray::new(vec![entry]).expect("array");
        let mut context = MultiSigContext::new();
        context
            .verify_quorum(
                &array,
                1,
                &[signer],
                |key, signature| verify_real(key, signature, &preimage),
                "quorum",
            )
            .expect("verify");
        assert_eq!(context.event_counts().get("quorum_verified"), Some(&1));
    }

    #[test]
    fn context_tracks_quorum_failure() {
        let object = object();
        let first = signed_entry(1, &object);
        let second = signed_entry(2, &object);
        let array = SortedSignatureArray::new(vec![first.clone()]).expect("array");
        let mut context = MultiSigContext::new();
        assert!(context
            .verify_quorum(
                &array,
                2,
                &[first.signer, second.signer],
                |_, _| Ok(()),
                "quorum-fail",
            )
            .is_err());
        assert_eq!(context.event_counts().get("quorum_failed"), Some(&1));
    }

    #[test]
    fn drain_events_clears_context() {
        let object = object();
        let mut context = MultiSigContext::new();
        context
            .create_sorted(vec![signed_entry(1, &object)], "create")
            .expect("create");
        assert_eq!(context.drain_events().len(), 1);
        assert!(context.drain_events().is_empty());
    }

    #[test]
    fn error_display_is_informative() {
        let error = MultiSigError::ThresholdExceedsSignerCount {
            threshold: 4,
            signer_count: 2,
        };
        let display = error.to_string();
        assert!(display.contains('4'));
        assert!(display.contains('2'));
    }

    #[test]
    fn quorum_result_display_is_informative() {
        let result = QuorumResult {
            quorum_met: true,
            valid_count: 2,
            invalid_count: 0,
            unauthorized_count: 1,
            total: 3,
            threshold: 2,
            invalid_signers: Vec::new(),
            unauthorized_signers: Vec::new(),
        };
        assert!(result.to_string().contains("2/3"));
    }

    #[test]
    fn error_serde_roundtrip_covers_threshold_variant() {
        let error = MultiSigError::ThresholdExceedsSignerCount {
            threshold: 3,
            signer_count: 2,
        };
        let value = serde_json::to_value(&error).expect("serialize");
        let restored: MultiSigError = serde_json::from_value(value).expect("deserialize");
        assert_eq!(restored, error);
    }

    #[test]
    fn event_serde_roundtrip() {
        let event = MultiSigEvent {
            event_type: MultiSigEventType::QuorumVerified {
                valid: 2,
                threshold: 2,
                total: 3,
            },
            trace_id: "trace".to_string(),
        };
        let value = serde_json::to_value(&event).expect("serialize");
        let restored: MultiSigEvent = serde_json::from_value(value).expect("deserialize");
        assert_eq!(restored, event);
    }

    #[test]
    fn context_default_is_empty() {
        assert!(MultiSigContext::default().event_counts().is_empty());
    }
}
