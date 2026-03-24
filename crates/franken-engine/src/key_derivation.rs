//! Epoch-scoped key derivation with domain separation.
//!
//! All derived keys are bound to a [`SecurityEpoch`] so that epoch
//! transitions automatically invalidate old-epoch keys.  Domain
//! separation prevents cross-domain key confusion: keys derived for
//! `Symbol` and `Session` domains are cryptographically independent
//! even with the same master key and epoch.
//!
//! The derivation function is trait-based ([`KeyDeriver`]) so that
//! production code can plug in HKDF (RFC 5869) while tests use a
//! deterministic deriver.
//!
//! Plan references: Section 10.11 item 18, 9G.6 (epoch-scoped validity
//! + key derivation), Top-10 #5 (supply-chain trust), #10 (provenance).

use std::collections::BTreeMap;
use std::fmt;

use serde::{Deserialize, Serialize};

use crate::hash_tiers::ContentHash;
use crate::security_epoch::SecurityEpoch;

// ---------------------------------------------------------------------------
// KeyDomain — domain separation taxonomy
// ---------------------------------------------------------------------------

/// Key domain for domain-separated derivation.
///
/// Each domain has a fixed, well-known separator byte string that
/// ensures keys derived for different purposes are cryptographically
/// independent.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
pub enum KeyDomain {
    /// Symbol table integrity (HMAC of symbol names).
    Symbol,
    /// Per-extension-session MAC key for authenticated hostcall channels.
    Session,
    /// Signing key for decision receipts and evidence entries.
    Authentication,
    /// Key for evidence ledger entry integrity.
    Evidence,
    /// Key for attestation signing.
    Attestation,
}

impl KeyDomain {
    /// The fixed domain separator byte string.
    ///
    /// These are unique, well-known prefixes ensuring cross-domain
    /// independence even with identical master key and epoch.
    pub fn separator(&self) -> &'static [u8] {
        match self {
            Self::Symbol => b"franken::symbol::",
            Self::Session => b"franken::session::",
            Self::Authentication => b"franken::auth::",
            Self::Evidence => b"franken::evidence::",
            Self::Attestation => b"franken::attestation::",
        }
    }

    /// All domain variants, for exhaustive iteration.
    pub const ALL: &'static [KeyDomain] = &[
        KeyDomain::Symbol,
        KeyDomain::Session,
        KeyDomain::Authentication,
        KeyDomain::Evidence,
        KeyDomain::Attestation,
    ];
}

impl fmt::Display for KeyDomain {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let name = match self {
            Self::Symbol => "symbol",
            Self::Session => "session",
            Self::Authentication => "authentication",
            Self::Evidence => "evidence",
            Self::Attestation => "attestation",
        };
        f.write_str(name)
    }
}

// ---------------------------------------------------------------------------
// DerivationContext — additional binding context
// ---------------------------------------------------------------------------

/// Additional binding context for key derivation.
///
/// Canonically serialized to bytes for inclusion in the derivation
/// input.  Deterministic serialization is required so that the same
/// logical context always produces the same derived key.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
pub struct DerivationContext {
    /// Ordered key-value pairs forming the context.
    /// Uses `BTreeMap` for deterministic ordering.
    entries: BTreeMap<String, String>,
}

impl DerivationContext {
    /// Empty context (no additional binding).
    pub fn empty() -> Self {
        Self {
            entries: BTreeMap::new(),
        }
    }

    /// Create from a single key-value pair.
    pub fn with(key: impl Into<String>, value: impl Into<String>) -> Self {
        let mut entries = BTreeMap::new();
        entries.insert(key.into(), value.into());
        Self { entries }
    }

    /// Add a binding to the context.
    pub fn add(&mut self, key: impl Into<String>, value: impl Into<String>) {
        self.entries.insert(key.into(), value.into());
    }

    /// Canonical byte serialization for derivation input.
    ///
    /// Format: `key1=value1\0key2=value2\0...` (sorted by key, NUL-separated).
    pub fn to_canonical_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::new();
        for (i, (k, v)) in self.entries.iter().enumerate() {
            if i > 0 {
                bytes.push(0); // NUL separator
            }
            bytes.extend_from_slice(k.as_bytes());
            bytes.push(b'=');
            bytes.extend_from_slice(v.as_bytes());
        }
        bytes
    }

    /// Number of entries in the context.
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
}

// ---------------------------------------------------------------------------
// DerivedKey — epoch-bound key material
// ---------------------------------------------------------------------------

/// Epoch-bound derived key material.
///
/// The key is valid only for the epoch in which it was derived.
/// Key bytes should be zeroized on drop in production (via `Zeroize`
/// trait when crypto dependencies are available).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DerivedKey {
    /// The derived key bytes.
    pub key_bytes: Vec<u8>,
    /// The domain for which this key was derived.
    pub domain: KeyDomain,
    /// The epoch in which this key was derived and is valid.
    pub epoch: SecurityEpoch,
    /// Hash of the derivation context (not the context itself).
    pub context_hash: Vec<u8>,
}

impl DerivedKey {
    /// Check whether this key is valid for a given epoch.
    pub fn is_valid_at(&self, epoch: SecurityEpoch) -> bool {
        self.epoch == epoch
    }
}

impl fmt::Display for DerivedKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "DerivedKey({}, {}, {} bytes)",
            self.domain,
            self.epoch,
            self.key_bytes.len()
        )
    }
}

// ---------------------------------------------------------------------------
// DerivationRequest — input to the derivation function
// ---------------------------------------------------------------------------

/// Input to a key derivation function.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DerivationRequest {
    /// Master key material (IKM in HKDF terms).
    pub master_key: Vec<u8>,
    /// Current security epoch.
    pub epoch: SecurityEpoch,
    /// Key domain (determines domain separator).
    pub domain: KeyDomain,
    /// Additional binding context.
    pub context: DerivationContext,
    /// Desired output key length in bytes.
    pub output_len: usize,
}

// ---------------------------------------------------------------------------
// KeyDerivationError
// ---------------------------------------------------------------------------

/// Errors from key derivation operations.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum KeyDerivationError {
    /// Master key is empty.
    EmptyMasterKey,
    /// Requested output length is zero.
    ZeroOutputLength,
    /// Requested output length exceeds maximum.
    OutputTooLong { requested: usize, max: usize },
    /// Key is being used outside its valid epoch.
    EpochMismatch {
        key_epoch: SecurityEpoch,
        current_epoch: SecurityEpoch,
    },
    /// Derivation function internal error.
    DerivationFailed { reason: String },
}

impl fmt::Display for KeyDerivationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::EmptyMasterKey => write!(f, "master key is empty"),
            Self::ZeroOutputLength => write!(f, "requested output length is zero"),
            Self::OutputTooLong { requested, max } => {
                write!(f, "output length {requested} exceeds max {max}")
            }
            Self::EpochMismatch {
                key_epoch,
                current_epoch,
            } => write!(
                f,
                "key epoch mismatch: key at {key_epoch}, current {current_epoch}"
            ),
            Self::DerivationFailed { reason } => write!(f, "derivation failed: {reason}"),
        }
    }
}

impl std::error::Error for KeyDerivationError {}

// ---------------------------------------------------------------------------
// KeyDeriver — trait for pluggable derivation functions
// ---------------------------------------------------------------------------

/// Trait for pluggable key derivation functions.
///
/// Production implementations should use HKDF (RFC 5869).
/// Test implementations can use deterministic, non-cryptographic
/// derivation for reproducibility.
pub trait KeyDeriver: fmt::Debug {
    /// Derive a key from the given request.
    fn derive(&self, request: &DerivationRequest) -> Result<DerivedKey, KeyDerivationError>;

    /// Maximum output key length supported.
    fn max_output_len(&self) -> usize;

    /// Stable human-readable algorithm label for audit events.
    ///
    /// This must not include secrets or other internal deriver state.
    fn algorithm_label(&self) -> &'static str {
        std::any::type_name::<Self>()
            .rsplit("::")
            .next()
            .unwrap_or("KeyDeriver")
    }
}

// ---------------------------------------------------------------------------
// DeterministicTestDeriver — for testing
// ---------------------------------------------------------------------------

/// Deterministic, non-cryptographic key deriver for testing.
///
/// Produces reproducible output by XOR-folding the concatenation of
/// domain separator, epoch (big-endian), and context bytes over the
/// master key.  **Not cryptographically secure** — use only in tests.
#[derive(Debug)]
pub struct DeterministicTestDeriver;

impl DeterministicTestDeriver {
    /// Maximum output length for the test deriver.
    pub const MAX_OUTPUT: usize = 256;
}

impl KeyDeriver for DeterministicTestDeriver {
    fn derive(&self, request: &DerivationRequest) -> Result<DerivedKey, KeyDerivationError> {
        if request.master_key.is_empty() {
            return Err(KeyDerivationError::EmptyMasterKey);
        }
        if request.output_len == 0 {
            return Err(KeyDerivationError::ZeroOutputLength);
        }
        if request.output_len > Self::MAX_OUTPUT {
            return Err(KeyDerivationError::OutputTooLong {
                requested: request.output_len,
                max: Self::MAX_OUTPUT,
            });
        }

        // Build derivation input: domain_sep || epoch_be || context_bytes
        let mut input = Vec::new();
        input.extend_from_slice(request.domain.separator());
        input.extend_from_slice(&request.epoch.as_u64().to_be_bytes());
        input.extend_from_slice(&request.context.to_canonical_bytes());

        // XOR-fold input over master key to produce output.
        let mk = &request.master_key;
        let mut output = vec![0u8; request.output_len];
        for (i, byte) in input.iter().enumerate() {
            output[i % request.output_len] ^= byte ^ mk[i % mk.len()];
        }
        // Second pass: mix position-dependent entropy.
        for i in 0..request.output_len {
            output[i] = output[i]
                .wrapping_add(mk[i % mk.len()])
                .wrapping_add(i as u8);
        }

        // Context hash: collision-resistant hash for determinism.
        let ctx_bytes = request.context.to_canonical_bytes();
        let ctx_hash = ContentHash::compute(&ctx_bytes);

        Ok(DerivedKey {
            key_bytes: output,
            domain: request.domain,
            epoch: request.epoch,
            context_hash: ctx_hash.as_bytes().to_vec(),
        })
    }

    fn max_output_len(&self) -> usize {
        Self::MAX_OUTPUT
    }
}

// ---------------------------------------------------------------------------
// DerivationEvent — structured evidence for key derivations
// ---------------------------------------------------------------------------

/// Structured evidence emitted for every key derivation event.
///
/// Never contains actual key material — only metadata for audit.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DerivationEvent {
    /// Key domain.
    pub domain: KeyDomain,
    /// Epoch in which the key was derived.
    pub epoch: SecurityEpoch,
    /// Hash of the derivation context (never the raw context).
    pub context_hash: Vec<u8>,
    /// Name of the derivation algorithm used.
    pub algorithm: String,
    /// Opaque trace identifier for correlation.
    pub trace_id: String,
}

// ---------------------------------------------------------------------------
// EpochKeyCache — epoch-scoped key cache with invalidation
// ---------------------------------------------------------------------------

/// Cache key for the epoch key cache.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
struct CacheKey {
    domain: KeyDomain,
    context_hash: Vec<u8>,
}

/// Epoch-scoped key cache with automatic invalidation.
///
/// Caches derived keys for the current epoch.  When the epoch advances,
/// all cached keys are invalidated (cleared).  Uses `BTreeMap` for
/// deterministic ordering.
#[derive(Debug)]
pub struct EpochKeyCache<D: KeyDeriver> {
    deriver: D,
    master_key: Vec<u8>,
    current_epoch: SecurityEpoch,
    cache: BTreeMap<CacheKey, DerivedKey>,
    events: Vec<DerivationEvent>,
    output_len: usize,
}

impl<D: KeyDeriver> EpochKeyCache<D> {
    /// Create a new cache with the given deriver, master key, and epoch.
    pub fn new(deriver: D, master_key: Vec<u8>, epoch: SecurityEpoch, output_len: usize) -> Self {
        Self {
            deriver,
            master_key,
            current_epoch: epoch,
            cache: BTreeMap::new(),
            events: Vec::new(),
            output_len,
        }
    }

    /// The current epoch of this cache.
    pub fn current_epoch(&self) -> SecurityEpoch {
        self.current_epoch
    }

    /// Advance to a new epoch, invalidating all cached keys.
    ///
    /// The new epoch must be strictly greater than the current epoch.
    pub fn advance_epoch(&mut self, new_epoch: SecurityEpoch) -> Result<(), KeyDerivationError> {
        if new_epoch <= self.current_epoch {
            return Err(KeyDerivationError::EpochMismatch {
                key_epoch: self.current_epoch,
                current_epoch: new_epoch,
            });
        }
        self.cache.clear();
        self.current_epoch = new_epoch;
        Ok(())
    }

    /// Derive or retrieve a cached key for the given domain and context.
    pub fn get_or_derive(
        &mut self,
        domain: KeyDomain,
        context: &DerivationContext,
        trace_id: &str,
    ) -> Result<&DerivedKey, KeyDerivationError> {
        let ctx_bytes = context.to_canonical_bytes();
        let ctx_hash = ContentHash::compute(&ctx_bytes);
        let ctx_hash_bytes = ctx_hash.as_bytes().to_vec();

        let cache_key = CacheKey {
            domain,
            context_hash: ctx_hash_bytes.clone(),
        };

        if !self.cache.contains_key(&cache_key) {
            let request = DerivationRequest {
                master_key: self.master_key.clone(),
                epoch: self.current_epoch,
                domain,
                context: context.clone(),
                output_len: self.output_len,
            };

            let derived = self.deriver.derive(&request)?;

            self.events.push(DerivationEvent {
                domain,
                epoch: self.current_epoch,
                context_hash: ctx_hash_bytes,
                algorithm: self.deriver.algorithm_label().to_string(),
                trace_id: trace_id.to_string(),
            });

            self.cache.insert(cache_key.clone(), derived);
        }

        Ok(self.cache.get(&cache_key).expect("just inserted"))
    }

    /// Validate that a derived key is still valid for the current epoch.
    pub fn validate_key(&self, key: &DerivedKey) -> Result<(), KeyDerivationError> {
        if key.epoch != self.current_epoch {
            return Err(KeyDerivationError::EpochMismatch {
                key_epoch: key.epoch,
                current_epoch: self.current_epoch,
            });
        }
        Ok(())
    }

    /// Number of cached keys.
    pub fn cached_count(&self) -> usize {
        self.cache.len()
    }

    /// Derivation events recorded by this cache.
    pub fn events(&self) -> &[DerivationEvent] {
        &self.events
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn test_master_key() -> Vec<u8> {
        b"test-master-key-32-bytes-long!!!".to_vec()
    }

    // -- KeyDomain basics --

    #[test]
    fn all_domains_have_unique_separators() {
        let seps: Vec<&[u8]> = KeyDomain::ALL.iter().map(|d| d.separator()).collect();
        for (i, a) in seps.iter().enumerate() {
            for (j, b) in seps.iter().enumerate() {
                if i != j {
                    assert_ne!(a, b, "domains {:?} and {:?} share separator", i, j);
                }
            }
        }
    }

    #[test]
    fn domain_display() {
        assert_eq!(KeyDomain::Symbol.to_string(), "symbol");
        assert_eq!(KeyDomain::Session.to_string(), "session");
        assert_eq!(KeyDomain::Authentication.to_string(), "authentication");
        assert_eq!(KeyDomain::Evidence.to_string(), "evidence");
        assert_eq!(KeyDomain::Attestation.to_string(), "attestation");
    }

    // -- DerivationContext --

    #[test]
    fn empty_context_produces_empty_bytes() {
        let ctx = DerivationContext::empty();
        assert!(ctx.to_canonical_bytes().is_empty());
        assert!(ctx.is_empty());
    }

    #[test]
    fn context_canonical_bytes_are_deterministic() {
        let mut ctx = DerivationContext::empty();
        ctx.add("ext_id", "abc");
        ctx.add("session_id", "xyz");
        let bytes1 = ctx.to_canonical_bytes();
        let bytes2 = ctx.to_canonical_bytes();
        assert_eq!(bytes1, bytes2);
    }

    #[test]
    fn context_ordering_is_deterministic_regardless_of_insertion_order() {
        let mut ctx1 = DerivationContext::empty();
        ctx1.add("b_key", "val2");
        ctx1.add("a_key", "val1");

        let mut ctx2 = DerivationContext::empty();
        ctx2.add("a_key", "val1");
        ctx2.add("b_key", "val2");

        assert_eq!(ctx1.to_canonical_bytes(), ctx2.to_canonical_bytes());
    }

    // -- DeterministicTestDeriver --

    #[test]
    fn derive_produces_correct_length() {
        let deriver = DeterministicTestDeriver;
        let request = DerivationRequest {
            master_key: test_master_key(),
            epoch: SecurityEpoch::from_raw(1),
            domain: KeyDomain::Symbol,
            context: DerivationContext::empty(),
            output_len: 32,
        };
        let key = deriver.derive(&request).expect("derive");
        assert_eq!(key.key_bytes.len(), 32);
        assert_eq!(key.domain, KeyDomain::Symbol);
        assert_eq!(key.epoch, SecurityEpoch::from_raw(1));
    }

    #[test]
    fn derive_is_deterministic() {
        let deriver = DeterministicTestDeriver;
        let request = DerivationRequest {
            master_key: test_master_key(),
            epoch: SecurityEpoch::from_raw(5),
            domain: KeyDomain::Session,
            context: DerivationContext::with("ext", "test-ext"),
            output_len: 32,
        };
        let key1 = deriver.derive(&request).expect("derive");
        let key2 = deriver.derive(&request).expect("derive");
        assert_eq!(key1.key_bytes, key2.key_bytes);
    }

    #[test]
    fn different_domains_produce_different_keys() {
        let deriver = DeterministicTestDeriver;
        let mk = test_master_key();
        let epoch = SecurityEpoch::from_raw(1);
        let ctx = DerivationContext::empty();

        let keys: Vec<DerivedKey> = KeyDomain::ALL
            .iter()
            .map(|d| {
                deriver
                    .derive(&DerivationRequest {
                        master_key: mk.clone(),
                        epoch,
                        domain: *d,
                        context: ctx.clone(),
                        output_len: 32,
                    })
                    .expect("derive")
            })
            .collect();

        // All pairwise distinct.
        for (i, a) in keys.iter().enumerate() {
            for (j, b) in keys.iter().enumerate() {
                if i != j {
                    assert_ne!(
                        a.key_bytes, b.key_bytes,
                        "domains {} and {} produced same key",
                        a.domain, b.domain
                    );
                }
            }
        }
    }

    #[test]
    fn different_epochs_produce_different_keys() {
        let deriver = DeterministicTestDeriver;
        let mk = test_master_key();
        let ctx = DerivationContext::empty();

        let key_e1 = deriver
            .derive(&DerivationRequest {
                master_key: mk.clone(),
                epoch: SecurityEpoch::from_raw(1),
                domain: KeyDomain::Symbol,
                context: ctx.clone(),
                output_len: 32,
            })
            .expect("derive");

        let key_e2 = deriver
            .derive(&DerivationRequest {
                master_key: mk,
                epoch: SecurityEpoch::from_raw(2),
                domain: KeyDomain::Symbol,
                context: ctx,
                output_len: 32,
            })
            .expect("derive");

        assert_ne!(key_e1.key_bytes, key_e2.key_bytes);
    }

    #[test]
    fn different_contexts_produce_different_keys() {
        let deriver = DeterministicTestDeriver;
        let mk = test_master_key();
        let epoch = SecurityEpoch::from_raw(1);

        let key1 = deriver
            .derive(&DerivationRequest {
                master_key: mk.clone(),
                epoch,
                domain: KeyDomain::Session,
                context: DerivationContext::with("ext", "alpha"),
                output_len: 32,
            })
            .expect("derive");

        let key2 = deriver
            .derive(&DerivationRequest {
                master_key: mk,
                epoch,
                domain: KeyDomain::Session,
                context: DerivationContext::with("ext", "beta"),
                output_len: 32,
            })
            .expect("derive");

        assert_ne!(key1.key_bytes, key2.key_bytes);
    }

    #[test]
    fn derive_rejects_empty_master_key() {
        let deriver = DeterministicTestDeriver;
        let err = deriver
            .derive(&DerivationRequest {
                master_key: vec![],
                epoch: SecurityEpoch::from_raw(1),
                domain: KeyDomain::Symbol,
                context: DerivationContext::empty(),
                output_len: 32,
            })
            .unwrap_err();
        assert_eq!(err, KeyDerivationError::EmptyMasterKey);
    }

    #[test]
    fn derive_rejects_zero_output_length() {
        let deriver = DeterministicTestDeriver;
        let err = deriver
            .derive(&DerivationRequest {
                master_key: test_master_key(),
                epoch: SecurityEpoch::from_raw(1),
                domain: KeyDomain::Symbol,
                context: DerivationContext::empty(),
                output_len: 0,
            })
            .unwrap_err();
        assert_eq!(err, KeyDerivationError::ZeroOutputLength);
    }

    #[test]
    fn derive_rejects_excessive_output_length() {
        let deriver = DeterministicTestDeriver;
        let err = deriver
            .derive(&DerivationRequest {
                master_key: test_master_key(),
                epoch: SecurityEpoch::from_raw(1),
                domain: KeyDomain::Symbol,
                context: DerivationContext::empty(),
                output_len: 1000,
            })
            .unwrap_err();
        assert!(matches!(
            err,
            KeyDerivationError::OutputTooLong {
                requested: 1000,
                ..
            }
        ));
    }

    // -- DerivedKey validation --

    #[test]
    fn derived_key_valid_at_same_epoch() {
        let key = DerivedKey {
            key_bytes: vec![1, 2, 3],
            domain: KeyDomain::Symbol,
            epoch: SecurityEpoch::from_raw(5),
            context_hash: vec![0],
        };
        assert!(key.is_valid_at(SecurityEpoch::from_raw(5)));
    }

    #[test]
    fn derived_key_invalid_at_different_epoch() {
        let key = DerivedKey {
            key_bytes: vec![1, 2, 3],
            domain: KeyDomain::Symbol,
            epoch: SecurityEpoch::from_raw(5),
            context_hash: vec![0],
        };
        assert!(!key.is_valid_at(SecurityEpoch::from_raw(6)));
    }

    // -- EpochKeyCache --

    #[test]
    fn cache_derives_and_caches() {
        let mut cache = EpochKeyCache::new(
            DeterministicTestDeriver,
            test_master_key(),
            SecurityEpoch::from_raw(1),
            32,
        );
        assert_eq!(cache.cached_count(), 0);

        let ctx = DerivationContext::with("ext", "test");
        cache
            .get_or_derive(KeyDomain::Session, &ctx, "trace-1")
            .expect("derive");
        assert_eq!(cache.cached_count(), 1);

        // Second call should hit cache (no new event).
        cache
            .get_or_derive(KeyDomain::Session, &ctx, "trace-2")
            .expect("cached");
        assert_eq!(cache.cached_count(), 1);
        assert_eq!(cache.events().len(), 1); // only one derivation event
    }

    #[test]
    fn cache_returns_same_key_on_cache_hit() {
        let mut cache = EpochKeyCache::new(
            DeterministicTestDeriver,
            test_master_key(),
            SecurityEpoch::from_raw(1),
            32,
        );
        let ctx = DerivationContext::with("ext", "test");
        let key1 = cache
            .get_or_derive(KeyDomain::Session, &ctx, "t1")
            .expect("derive")
            .clone();
        let key2 = cache
            .get_or_derive(KeyDomain::Session, &ctx, "t2")
            .expect("cached")
            .clone();
        assert_eq!(key1.key_bytes, key2.key_bytes);
    }

    #[test]
    fn cache_invalidates_on_epoch_advance() {
        let mut cache = EpochKeyCache::new(
            DeterministicTestDeriver,
            test_master_key(),
            SecurityEpoch::from_raw(1),
            32,
        );
        let ctx = DerivationContext::empty();

        // Derive a key at epoch 1.
        let key_e1 = cache
            .get_or_derive(KeyDomain::Symbol, &ctx, "t1")
            .expect("derive")
            .clone();
        assert_eq!(cache.cached_count(), 1);

        // Advance to epoch 2 — cache should be empty.
        cache
            .advance_epoch(SecurityEpoch::from_raw(2))
            .expect("advance");
        assert_eq!(cache.cached_count(), 0);
        assert_eq!(cache.current_epoch(), SecurityEpoch::from_raw(2));

        // Derive at epoch 2 — should produce a different key.
        let key_e2 = cache
            .get_or_derive(KeyDomain::Symbol, &ctx, "t2")
            .expect("derive")
            .clone();
        assert_ne!(key_e1.key_bytes, key_e2.key_bytes);
        assert_eq!(key_e2.epoch, SecurityEpoch::from_raw(2));
    }

    #[test]
    fn cache_rejects_non_monotonic_epoch_advance() {
        let mut cache = EpochKeyCache::new(
            DeterministicTestDeriver,
            test_master_key(),
            SecurityEpoch::from_raw(5),
            32,
        );
        let err = cache.advance_epoch(SecurityEpoch::from_raw(3)).unwrap_err();
        assert!(matches!(err, KeyDerivationError::EpochMismatch { .. }));
    }

    #[test]
    fn cache_rejects_same_epoch_advance() {
        let mut cache = EpochKeyCache::new(
            DeterministicTestDeriver,
            test_master_key(),
            SecurityEpoch::from_raw(5),
            32,
        );
        let err = cache.advance_epoch(SecurityEpoch::from_raw(5)).unwrap_err();
        assert!(matches!(err, KeyDerivationError::EpochMismatch { .. }));
    }

    #[test]
    fn cache_validates_key_at_current_epoch() {
        let cache = EpochKeyCache::new(
            DeterministicTestDeriver,
            test_master_key(),
            SecurityEpoch::from_raw(3),
            32,
        );
        let valid_key = DerivedKey {
            key_bytes: vec![1],
            domain: KeyDomain::Symbol,
            epoch: SecurityEpoch::from_raw(3),
            context_hash: vec![],
        };
        assert!(cache.validate_key(&valid_key).is_ok());
    }

    #[test]
    fn cache_rejects_key_from_old_epoch() {
        let cache = EpochKeyCache::new(
            DeterministicTestDeriver,
            test_master_key(),
            SecurityEpoch::from_raw(5),
            32,
        );
        let old_key = DerivedKey {
            key_bytes: vec![1],
            domain: KeyDomain::Symbol,
            epoch: SecurityEpoch::from_raw(3),
            context_hash: vec![],
        };
        let err = cache.validate_key(&old_key).unwrap_err();
        assert!(matches!(err, KeyDerivationError::EpochMismatch { .. }));
    }

    #[test]
    fn cache_records_derivation_events() {
        let mut cache = EpochKeyCache::new(
            DeterministicTestDeriver,
            test_master_key(),
            SecurityEpoch::from_raw(1),
            32,
        );
        cache
            .get_or_derive(KeyDomain::Symbol, &DerivationContext::empty(), "trace-abc")
            .expect("derive");
        cache
            .get_or_derive(
                KeyDomain::Session,
                &DerivationContext::with("ext", "foo"),
                "trace-def",
            )
            .expect("derive");

        let events = cache.events();
        assert_eq!(events.len(), 2);
        assert_eq!(events[0].domain, KeyDomain::Symbol);
        assert_eq!(events[0].algorithm, "DeterministicTestDeriver");
        assert_eq!(events[0].trace_id, "trace-abc");
        assert_eq!(events[1].domain, KeyDomain::Session);
        assert_eq!(events[1].algorithm, "DeterministicTestDeriver");
        assert_eq!(events[1].trace_id, "trace-def");
    }

    #[derive(Debug)]
    struct SecretDebugDeriver {
        secret_material: &'static str,
    }

    impl KeyDeriver for SecretDebugDeriver {
        fn derive(&self, request: &DerivationRequest) -> Result<DerivedKey, KeyDerivationError> {
            DeterministicTestDeriver.derive(request)
        }

        fn max_output_len(&self) -> usize {
            DeterministicTestDeriver::MAX_OUTPUT
        }
    }

    #[test]
    fn cache_event_algorithm_label_does_not_leak_debug_state() {
        let deriver = SecretDebugDeriver {
            secret_material: "do-not-log-me",
        };
        assert_eq!(deriver.secret_material, "do-not-log-me");
        assert!(
            format!("{deriver:?}").contains("do-not-log-me"),
            "test deriver debug output should demonstrate the leak-prone shape"
        );

        let mut cache =
            EpochKeyCache::new(deriver, test_master_key(), SecurityEpoch::from_raw(1), 32);

        cache
            .get_or_derive(
                KeyDomain::Session,
                &DerivationContext::empty(),
                "trace-secret",
            )
            .expect("derive");

        let event = cache.events().first().expect("event should exist");
        assert_eq!(event.algorithm, "SecretDebugDeriver");
        assert!(
            !event.algorithm.contains("do-not-log-me"),
            "algorithm label must not leak deriver debug state"
        );
    }

    // -- Integration: old key rejected after epoch advance --

    #[test]
    fn old_epoch_key_rejected_after_advance() {
        let mut cache = EpochKeyCache::new(
            DeterministicTestDeriver,
            test_master_key(),
            SecurityEpoch::from_raw(1),
            32,
        );
        let ctx = DerivationContext::with("ext", "test");
        let old_key = cache
            .get_or_derive(KeyDomain::Session, &ctx, "t1")
            .expect("derive")
            .clone();

        // Advance epoch.
        cache
            .advance_epoch(SecurityEpoch::from_raw(2))
            .expect("advance");

        // Old key should be rejected.
        let err = cache.validate_key(&old_key).unwrap_err();
        assert!(matches!(
            err,
            KeyDerivationError::EpochMismatch {
                key_epoch,
                current_epoch,
            } if key_epoch.as_u64() == 1 && current_epoch.as_u64() == 2
        ));
    }

    // -- Error display --

    #[test]
    fn error_display() {
        assert_eq!(
            KeyDerivationError::EmptyMasterKey.to_string(),
            "master key is empty"
        );
        assert_eq!(
            KeyDerivationError::ZeroOutputLength.to_string(),
            "requested output length is zero"
        );
        assert_eq!(
            KeyDerivationError::OutputTooLong {
                requested: 500,
                max: 256
            }
            .to_string(),
            "output length 500 exceeds max 256"
        );
    }

    #[test]
    fn derived_key_display() {
        let key = DerivedKey {
            key_bytes: vec![0; 32],
            domain: KeyDomain::Authentication,
            epoch: SecurityEpoch::from_raw(7),
            context_hash: vec![],
        };
        assert_eq!(
            key.to_string(),
            "DerivedKey(authentication, epoch:7, 32 bytes)"
        );
    }

    // -- Serialization --

    #[test]
    fn derived_key_serialization_round_trip() {
        let key = DerivedKey {
            key_bytes: vec![1, 2, 3, 4],
            domain: KeyDomain::Session,
            epoch: SecurityEpoch::from_raw(5),
            context_hash: vec![10, 20],
        };
        let json = serde_json::to_string(&key).expect("serialize");
        let restored: DerivedKey = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(key, restored);
    }

    #[test]
    fn derivation_event_serialization_round_trip() {
        let event = DerivationEvent {
            domain: KeyDomain::Authentication,
            epoch: SecurityEpoch::from_raw(3),
            context_hash: vec![5, 6, 7],
            algorithm: "DeterministicTestDeriver".to_string(),
            trace_id: "trace-xyz".to_string(),
        };
        let json = serde_json::to_string(&event).expect("serialize");
        let restored: DerivationEvent = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(event, restored);
    }

    #[test]
    fn derivation_context_serialization_round_trip() {
        let mut ctx = DerivationContext::empty();
        ctx.add("ext_id", "abc");
        ctx.add("session", "xyz");
        let json = serde_json::to_string(&ctx).expect("serialize");
        let restored: DerivationContext = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(ctx, restored);
    }

    // -- Enrichment: Ord, std::error --

    #[test]
    fn key_domain_ordering() {
        assert!(KeyDomain::Symbol < KeyDomain::Session);
        assert!(KeyDomain::Session < KeyDomain::Authentication);
        assert!(KeyDomain::Authentication < KeyDomain::Evidence);
        assert!(KeyDomain::Evidence < KeyDomain::Attestation);
    }

    #[test]
    fn key_derivation_error_implements_std_error() {
        let variants: Vec<Box<dyn std::error::Error>> = vec![
            Box::new(KeyDerivationError::EmptyMasterKey),
            Box::new(KeyDerivationError::ZeroOutputLength),
            Box::new(KeyDerivationError::OutputTooLong {
                requested: 500,
                max: 256,
            }),
            Box::new(KeyDerivationError::EpochMismatch {
                key_epoch: SecurityEpoch::from_raw(1),
                current_epoch: SecurityEpoch::from_raw(5),
            }),
            Box::new(KeyDerivationError::DerivationFailed {
                reason: "test".into(),
            }),
        ];
        let mut displays = std::collections::BTreeSet::new();
        for v in &variants {
            let msg = format!("{v}");
            assert!(!msg.is_empty());
            displays.insert(msg);
        }
        assert_eq!(
            displays.len(),
            5,
            "all 5 variants produce distinct messages"
        );
    }

    #[test]
    fn error_serialization_round_trip() {
        let errors = vec![
            KeyDerivationError::EmptyMasterKey,
            KeyDerivationError::ZeroOutputLength,
            KeyDerivationError::OutputTooLong {
                requested: 500,
                max: 256,
            },
            KeyDerivationError::EpochMismatch {
                key_epoch: SecurityEpoch::from_raw(1),
                current_epoch: SecurityEpoch::from_raw(5),
            },
            KeyDerivationError::DerivationFailed {
                reason: "test".to_string(),
            },
        ];
        for err in &errors {
            let json = serde_json::to_string(err).expect("serialize");
            let restored: KeyDerivationError = serde_json::from_str(&json).expect("deserialize");
            assert_eq!(*err, restored);
        }
    }

    // ── Enrichment: DerivationContext edge cases ─────────────────

    #[test]
    fn context_with_single_entry() {
        let ctx = DerivationContext::with("key", "val");
        assert_eq!(ctx.len(), 1);
        assert!(!ctx.is_empty());
        assert_eq!(ctx.to_canonical_bytes(), b"key=val");
    }

    #[test]
    fn context_nul_separator_between_entries() {
        let mut ctx = DerivationContext::empty();
        ctx.add("a", "1");
        ctx.add("b", "2");
        let bytes = ctx.to_canonical_bytes();
        // Format: a=1\0b=2
        assert_eq!(bytes, b"a=1\0b=2");
    }

    #[test]
    fn context_overwrite_entry() {
        let mut ctx = DerivationContext::empty();
        ctx.add("k", "old");
        ctx.add("k", "new");
        assert_eq!(ctx.len(), 1);
        assert_eq!(ctx.to_canonical_bytes(), b"k=new");
    }

    #[test]
    fn context_empty_value() {
        let ctx = DerivationContext::with("key", "");
        assert_eq!(ctx.to_canonical_bytes(), b"key=");
    }

    #[test]
    fn context_empty_key() {
        let ctx = DerivationContext::with("", "val");
        assert_eq!(ctx.to_canonical_bytes(), b"=val");
    }

    // ── Enrichment: output length boundaries ─────────────────────

    #[test]
    fn derive_output_len_one_succeeds() {
        let deriver = DeterministicTestDeriver;
        let key = deriver
            .derive(&DerivationRequest {
                master_key: test_master_key(),
                epoch: SecurityEpoch::from_raw(1),
                domain: KeyDomain::Symbol,
                context: DerivationContext::empty(),
                output_len: 1,
            })
            .unwrap();
        assert_eq!(key.key_bytes.len(), 1);
    }

    #[test]
    fn derive_output_len_max_succeeds() {
        let deriver = DeterministicTestDeriver;
        let key = deriver
            .derive(&DerivationRequest {
                master_key: test_master_key(),
                epoch: SecurityEpoch::from_raw(1),
                domain: KeyDomain::Symbol,
                context: DerivationContext::empty(),
                output_len: DeterministicTestDeriver::MAX_OUTPUT,
            })
            .unwrap();
        assert_eq!(key.key_bytes.len(), 256);
    }

    #[test]
    fn derive_output_len_max_plus_one_fails() {
        let deriver = DeterministicTestDeriver;
        let err = deriver
            .derive(&DerivationRequest {
                master_key: test_master_key(),
                epoch: SecurityEpoch::from_raw(1),
                domain: KeyDomain::Symbol,
                context: DerivationContext::empty(),
                output_len: DeterministicTestDeriver::MAX_OUTPUT + 1,
            })
            .unwrap_err();
        assert!(matches!(
            err,
            KeyDerivationError::OutputTooLong {
                requested: 257,
                max: 256,
            }
        ));
    }

    // ── Enrichment: master key length sensitivity ────────────────

    #[test]
    fn different_master_keys_produce_different_keys() {
        let deriver = DeterministicTestDeriver;
        let epoch = SecurityEpoch::from_raw(1);
        let ctx = DerivationContext::empty();

        let key_a = deriver
            .derive(&DerivationRequest {
                master_key: b"master-key-alpha-32-bytes-long!!".to_vec(),
                epoch,
                domain: KeyDomain::Symbol,
                context: ctx.clone(),
                output_len: 32,
            })
            .unwrap();

        let key_b = deriver
            .derive(&DerivationRequest {
                master_key: b"master-key-bravo-32-bytes-long!!".to_vec(),
                epoch,
                domain: KeyDomain::Symbol,
                context: ctx,
                output_len: 32,
            })
            .unwrap();

        assert_ne!(key_a.key_bytes, key_b.key_bytes);
    }

    #[test]
    fn single_byte_master_key_works() {
        let deriver = DeterministicTestDeriver;
        let key = deriver
            .derive(&DerivationRequest {
                master_key: vec![0xff],
                epoch: SecurityEpoch::from_raw(1),
                domain: KeyDomain::Symbol,
                context: DerivationContext::empty(),
                output_len: 32,
            })
            .unwrap();
        assert_eq!(key.key_bytes.len(), 32);
    }

    // ── Enrichment: DerivedKey validity ──────────────────────────

    #[test]
    fn derived_key_valid_at_genesis_epoch() {
        let key = DerivedKey {
            key_bytes: vec![1],
            domain: KeyDomain::Symbol,
            epoch: SecurityEpoch::GENESIS,
            context_hash: vec![],
        };
        assert!(key.is_valid_at(SecurityEpoch::GENESIS));
        assert!(!key.is_valid_at(SecurityEpoch::from_raw(1)));
    }

    // ── Enrichment: cache multi-domain ───────────────────────────

    #[test]
    fn cache_different_domains_cached_independently() {
        let mut cache = EpochKeyCache::new(
            DeterministicTestDeriver,
            test_master_key(),
            SecurityEpoch::from_raw(1),
            32,
        );
        let ctx = DerivationContext::empty();
        cache.get_or_derive(KeyDomain::Symbol, &ctx, "t1").unwrap();
        cache.get_or_derive(KeyDomain::Session, &ctx, "t2").unwrap();
        assert_eq!(cache.cached_count(), 2);
        assert_eq!(cache.events().len(), 2);
    }

    #[test]
    fn cache_epoch_advance_chain() {
        let mut cache = EpochKeyCache::new(
            DeterministicTestDeriver,
            test_master_key(),
            SecurityEpoch::from_raw(1),
            32,
        );
        let ctx = DerivationContext::empty();

        for epoch in 1..=5u64 {
            cache
                .get_or_derive(KeyDomain::Symbol, &ctx, &format!("t{epoch}"))
                .unwrap();
            assert_eq!(cache.cached_count(), 1);
            if epoch < 5 {
                cache
                    .advance_epoch(SecurityEpoch::from_raw(epoch + 1))
                    .unwrap();
                assert_eq!(cache.cached_count(), 0);
            }
        }
        assert_eq!(cache.events().len(), 5);
    }

    // ── Enrichment: context hash determinism ─────────────────────

    #[test]
    fn same_context_produces_same_context_hash() {
        let deriver = DeterministicTestDeriver;
        let mk = test_master_key();
        let ctx = DerivationContext::with("ext", "test");

        let key1 = deriver
            .derive(&DerivationRequest {
                master_key: mk.clone(),
                epoch: SecurityEpoch::from_raw(1),
                domain: KeyDomain::Symbol,
                context: ctx.clone(),
                output_len: 32,
            })
            .unwrap();

        let key2 = deriver
            .derive(&DerivationRequest {
                master_key: mk,
                epoch: SecurityEpoch::from_raw(1),
                domain: KeyDomain::Symbol,
                context: ctx,
                output_len: 32,
            })
            .unwrap();

        assert_eq!(key1.context_hash, key2.context_hash);
    }

    #[test]
    fn different_contexts_produce_different_context_hashes() {
        let deriver = DeterministicTestDeriver;
        let mk = test_master_key();

        let key1 = deriver
            .derive(&DerivationRequest {
                master_key: mk.clone(),
                epoch: SecurityEpoch::from_raw(1),
                domain: KeyDomain::Symbol,
                context: DerivationContext::with("ext", "alpha"),
                output_len: 32,
            })
            .unwrap();

        let key2 = deriver
            .derive(&DerivationRequest {
                master_key: mk,
                epoch: SecurityEpoch::from_raw(1),
                domain: KeyDomain::Symbol,
                context: DerivationContext::with("ext", "beta"),
                output_len: 32,
            })
            .unwrap();

        assert_ne!(key1.context_hash, key2.context_hash);
    }

    // ── Enrichment: max_output_len ───────────────────────────────

    #[test]
    fn deriver_max_output_len() {
        let deriver = DeterministicTestDeriver;
        assert_eq!(deriver.max_output_len(), 256);
    }

    // ── Enrichment: KeyDomain::ALL completeness ──────────────────

    #[test]
    fn key_domain_all_has_five_entries() {
        assert_eq!(KeyDomain::ALL.len(), 5);
    }

    #[test]
    fn all_domains_have_nonempty_separators() {
        for domain in KeyDomain::ALL {
            assert!(!domain.separator().is_empty());
        }
    }

    // ── Enrichment: DerivationRequest serde ──────────────────────

    #[test]
    fn derivation_request_serde_roundtrip() {
        let req = DerivationRequest {
            master_key: vec![1, 2, 3],
            epoch: SecurityEpoch::from_raw(5),
            domain: KeyDomain::Session,
            context: DerivationContext::with("k", "v"),
            output_len: 32,
        };
        let json = serde_json::to_string(&req).unwrap();
        let back: DerivationRequest = serde_json::from_str(&json).unwrap();
        assert_eq!(back, req);
    }

    // ── Enrichment: error display for EpochMismatch/DerivationFailed

    #[test]
    fn error_display_epoch_mismatch() {
        let err = KeyDerivationError::EpochMismatch {
            key_epoch: SecurityEpoch::from_raw(1),
            current_epoch: SecurityEpoch::from_raw(5),
        };
        let msg = err.to_string();
        assert!(msg.contains("1"));
        assert!(msg.contains("5"));
    }

    #[test]
    fn error_display_derivation_failed() {
        let err = KeyDerivationError::DerivationFailed {
            reason: "hardware fault".to_string(),
        };
        assert!(err.to_string().contains("hardware fault"));
    }

    // ── Enrichment: Display uniqueness, edge cases, determinism ────────

    #[test]
    fn key_domain_display_all_unique() {
        let mut displays = std::collections::BTreeSet::new();
        for domain in KeyDomain::ALL {
            displays.insert(domain.to_string());
        }
        assert_eq!(
            displays.len(),
            5,
            "all 5 KeyDomain variants have unique Display"
        );
    }

    #[test]
    fn key_domain_separator_all_unique() {
        let mut seps = std::collections::BTreeSet::new();
        for domain in KeyDomain::ALL {
            seps.insert(domain.separator().to_vec());
        }
        assert_eq!(seps.len(), 5, "all domains have unique separators");
    }

    #[test]
    fn key_domain_serde_roundtrip_all() {
        for domain in KeyDomain::ALL {
            let json = serde_json::to_string(domain).unwrap();
            let back: KeyDomain = serde_json::from_str(&json).unwrap();
            assert_eq!(*domain, back);
        }
    }

    #[test]
    fn cache_get_returns_cached_on_second_call() {
        let mut cache = EpochKeyCache::new(
            DeterministicTestDeriver,
            test_master_key(),
            SecurityEpoch::from_raw(1),
            32,
        );
        let ctx = DerivationContext::empty();
        let key1 = cache
            .get_or_derive(KeyDomain::Symbol, &ctx, "t1")
            .unwrap()
            .clone();
        // Second call should return the cached key (no new event).
        let key2 = cache
            .get_or_derive(KeyDomain::Symbol, &ctx, "t2")
            .unwrap()
            .clone();
        assert_eq!(key1.key_bytes, key2.key_bytes);
        // Only 1 derivation event, the second was a cache hit.
        assert_eq!(cache.events().len(), 1);
    }

    #[test]
    fn empty_master_key_rejected() {
        let deriver = DeterministicTestDeriver;
        let err = deriver
            .derive(&DerivationRequest {
                master_key: vec![],
                epoch: SecurityEpoch::from_raw(1),
                domain: KeyDomain::Symbol,
                context: DerivationContext::empty(),
                output_len: 32,
            })
            .unwrap_err();
        assert!(matches!(err, KeyDerivationError::EmptyMasterKey));
    }

    #[test]
    fn zero_output_length_rejected() {
        let deriver = DeterministicTestDeriver;
        let err = deriver
            .derive(&DerivationRequest {
                master_key: test_master_key(),
                epoch: SecurityEpoch::from_raw(1),
                domain: KeyDomain::Symbol,
                context: DerivationContext::empty(),
                output_len: 0,
            })
            .unwrap_err();
        assert!(matches!(err, KeyDerivationError::ZeroOutputLength));
    }

    #[test]
    fn derived_key_is_valid_at_correct_epoch() {
        let key = DerivedKey {
            key_bytes: vec![42],
            domain: KeyDomain::Authentication,
            epoch: SecurityEpoch::from_raw(7),
            context_hash: vec![],
        };
        assert!(key.is_valid_at(SecurityEpoch::from_raw(7)));
        assert!(!key.is_valid_at(SecurityEpoch::from_raw(6)));
        assert!(!key.is_valid_at(SecurityEpoch::from_raw(8)));
    }

    #[test]
    fn context_ordering_is_deterministic() {
        let mut ctx_a = DerivationContext::empty();
        ctx_a.add("z", "last");
        ctx_a.add("a", "first");
        let mut ctx_b = DerivationContext::empty();
        ctx_b.add("a", "first");
        ctx_b.add("z", "last");
        // BTreeMap ensures deterministic order regardless of insertion order
        assert_eq!(ctx_a.to_canonical_bytes(), ctx_b.to_canonical_bytes());
    }

    // ── Enrichment batch 5: copy/clone, JSON fields, separators ───────

    #[test]
    fn key_domain_copy_semantics() {
        let d = KeyDomain::Symbol;
        let copied = d;
        assert_eq!(d, copied);
    }

    #[test]
    fn derivation_context_clone_eq() {
        let mut ctx = DerivationContext::empty();
        ctx.add("k", "v");
        let cloned = ctx.clone();
        assert_eq!(ctx, cloned);
    }

    #[test]
    fn derivation_request_clone_eq() {
        let req = DerivationRequest {
            master_key: vec![1, 2, 3],
            epoch: SecurityEpoch::from_raw(5),
            domain: KeyDomain::Session,
            context: DerivationContext::with("k", "v"),
            output_len: 32,
        };
        let cloned = req.clone();
        assert_eq!(req, cloned);
    }

    #[test]
    fn derived_key_clone_eq() {
        let key = DerivedKey {
            key_bytes: vec![10, 20, 30],
            domain: KeyDomain::Evidence,
            epoch: SecurityEpoch::from_raw(2),
            context_hash: vec![99],
        };
        let cloned = key.clone();
        assert_eq!(key, cloned);
    }

    #[test]
    fn derivation_event_clone_eq() {
        let event = DerivationEvent {
            domain: KeyDomain::Attestation,
            epoch: SecurityEpoch::from_raw(4),
            context_hash: vec![1, 2],
            algorithm: "test".to_string(),
            trace_id: "t-1".to_string(),
        };
        let cloned = event.clone();
        assert_eq!(event, cloned);
    }

    #[test]
    fn derivation_event_json_fields_present() {
        let event = DerivationEvent {
            domain: KeyDomain::Symbol,
            epoch: SecurityEpoch::from_raw(1),
            context_hash: vec![5],
            algorithm: "DeterministicTestDeriver".to_string(),
            trace_id: "trace-001".to_string(),
        };
        let json = serde_json::to_string(&event).unwrap();
        assert!(json.contains("\"domain\""));
        assert!(json.contains("\"epoch\""));
        assert!(json.contains("\"context_hash\""));
        assert!(json.contains("\"algorithm\""));
        assert!(json.contains("\"trace_id\""));
    }

    #[test]
    fn derived_key_json_fields_present() {
        let key = DerivedKey {
            key_bytes: vec![1],
            domain: KeyDomain::Symbol,
            epoch: SecurityEpoch::from_raw(1),
            context_hash: vec![0],
        };
        let json = serde_json::to_string(&key).unwrap();
        assert!(json.contains("\"key_bytes\""));
        assert!(json.contains("\"domain\""));
        assert!(json.contains("\"epoch\""));
        assert!(json.contains("\"context_hash\""));
    }

    #[test]
    fn all_separators_start_with_franken_prefix() {
        for domain in KeyDomain::ALL {
            let sep = domain.separator();
            assert!(
                sep.starts_with(b"franken::"),
                "separator for {domain:?} must start with 'franken::'"
            );
        }
    }

    #[test]
    fn all_separators_end_with_double_colon() {
        for domain in KeyDomain::ALL {
            let sep = domain.separator();
            assert!(
                sep.ends_with(b"::"),
                "separator for {domain:?} must end with '::'"
            );
        }
    }

    #[test]
    fn cache_all_five_domains_produce_unique_keys() {
        let mut cache = EpochKeyCache::new(
            DeterministicTestDeriver,
            test_master_key(),
            SecurityEpoch::from_raw(1),
            32,
        );
        let ctx = DerivationContext::empty();
        let mut key_bytes_set = std::collections::BTreeSet::new();
        for domain in KeyDomain::ALL {
            let key = cache.get_or_derive(*domain, &ctx, "t").unwrap().clone();
            key_bytes_set.insert(key.key_bytes);
        }
        assert_eq!(key_bytes_set.len(), 5, "all 5 domains produce unique keys");
    }

    #[test]
    fn context_many_entries_canonical_sorted() {
        let mut ctx = DerivationContext::empty();
        ctx.add("zebra", "z");
        ctx.add("apple", "a");
        ctx.add("mango", "m");
        let bytes = ctx.to_canonical_bytes();
        let s = String::from_utf8_lossy(&bytes);
        // BTreeMap sorts keys alphabetically: apple, mango, zebra
        assert!(s.starts_with("apple=a"));
        assert!(s.contains("mango=m"));
        assert!(s.ends_with("zebra=z"));
    }

    #[test]
    fn derivation_request_json_field_output_len() {
        let req = DerivationRequest {
            master_key: vec![1],
            epoch: SecurityEpoch::from_raw(1),
            domain: KeyDomain::Symbol,
            context: DerivationContext::empty(),
            output_len: 64,
        };
        let json = serde_json::to_string(&req).unwrap();
        assert!(json.contains("\"output_len\""));
        assert!(json.contains("64"));
    }

    #[test]
    fn derived_key_display_contains_domain_epoch_bytes() {
        let key = DerivedKey {
            key_bytes: vec![0; 16],
            domain: KeyDomain::Evidence,
            epoch: SecurityEpoch::from_raw(3),
            context_hash: vec![],
        };
        let display = key.to_string();
        assert!(display.contains("evidence"));
        assert!(display.contains("3"));
        assert!(display.contains("16 bytes"));
    }

    #[test]
    fn cache_events_contain_correct_epoch() {
        let mut cache = EpochKeyCache::new(
            DeterministicTestDeriver,
            test_master_key(),
            SecurityEpoch::from_raw(10),
            32,
        );
        cache
            .get_or_derive(KeyDomain::Symbol, &DerivationContext::empty(), "t1")
            .unwrap();
        assert_eq!(cache.events()[0].epoch, SecurityEpoch::from_raw(10));

        cache.advance_epoch(SecurityEpoch::from_raw(11)).unwrap();
        cache
            .get_or_derive(KeyDomain::Symbol, &DerivationContext::empty(), "t2")
            .unwrap();
        assert_eq!(cache.events()[1].epoch, SecurityEpoch::from_raw(11));
    }

    #[test]
    fn key_domain_hash_consistent() {
        use std::hash::{Hash, Hasher};
        let d = KeyDomain::Authentication;
        let mut h1 = std::collections::hash_map::DefaultHasher::new();
        let mut h2 = std::collections::hash_map::DefaultHasher::new();
        d.hash(&mut h1);
        d.hash(&mut h2);
        assert_eq!(h1.finish(), h2.finish());
    }

    #[test]
    fn derivation_context_hash_consistent() {
        use std::hash::{Hash, Hasher};
        let ctx = DerivationContext::with("k", "v");
        let mut h1 = std::collections::hash_map::DefaultHasher::new();
        let mut h2 = std::collections::hash_map::DefaultHasher::new();
        ctx.hash(&mut h1);
        ctx.hash(&mut h2);
        assert_eq!(h1.finish(), h2.finish());
    }

    #[test]
    fn key_derivation_error_debug_not_empty() {
        let errors = [
            KeyDerivationError::EmptyMasterKey,
            KeyDerivationError::ZeroOutputLength,
            KeyDerivationError::OutputTooLong {
                requested: 1,
                max: 0,
            },
            KeyDerivationError::EpochMismatch {
                key_epoch: SecurityEpoch::from_raw(1),
                current_epoch: SecurityEpoch::from_raw(2),
            },
            KeyDerivationError::DerivationFailed { reason: "r".into() },
        ];
        for e in &errors {
            assert!(!format!("{e:?}").is_empty());
        }
    }
}
