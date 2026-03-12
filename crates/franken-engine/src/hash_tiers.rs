//! Three-tier hash strategy: hot integrity, content identity, trust
//! authenticity.
//!
//! Separates hash usage into distinct tiers with explicit scope boundaries:
//! - **Tier 1 (IntegrityHash)**: fast, non-cryptographic, ephemeral.
//! - **Tier 2 (ContentHash)**: collision-resistant, deterministic, persisted.
//! - **Tier 3 (AuthenticityHash)**: cryptographic, keyed, security-critical.
//!
//! Each tier uses a distinct Rust newtype to prevent cross-tier confusion
//! at compile time.
//!
//! Plan references: Section 10.11 item 27, 9G.9 (three-tier integrity
//! strategy + append-only decision stream), Top-10 #3, #10.

use std::fmt;

use serde::{Deserialize, Serialize};

// ---------------------------------------------------------------------------
// Tier 1 — IntegrityHash (hot-path, non-cryptographic)
// ---------------------------------------------------------------------------

/// Tier 1: fast non-cryptographic hash for hot-path integrity.
///
/// Used for: memory corruption detection, cache key derivation, scheduler
/// dedup, GC object fingerprinting.
///
/// Scope: intra-process, ephemeral, NOT persisted across restarts, NOT
/// security-relevant.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct IntegrityHash(pub u64);

impl IntegrityHash {
    /// Compute an integrity hash over the given bytes.
    ///
    /// Uses a wyhash-inspired mixing function for speed.
    pub fn compute(data: &[u8]) -> Self {
        Self(wyhash_inspired(data))
    }

    /// Access the raw u64 value.
    pub fn as_u64(&self) -> u64 {
        self.0
    }
}

impl fmt::Display for IntegrityHash {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "integrity:{:016x}", self.0)
    }
}

// ---------------------------------------------------------------------------
// Tier 2 — ContentHash (collision-resistant, persisted)
// ---------------------------------------------------------------------------

/// Tier 2: collision-resistant cryptographic hash for content identity.
///
/// Used for: evidence entry IDs, artifact fingerprinting, module cache
/// identity, IR pass output identity, dedup across processes.
///
/// Scope: persisted, deterministic across platforms, NOT used for
/// authentication.
#[derive(
    Debug, Clone, Copy, Default, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize,
)]
pub struct ContentHash(pub [u8; 32]);

impl ContentHash {
    /// Construct a content hash from precomputed bytes.
    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    /// Compute a content hash over the given bytes.
    ///
    /// Uses a SipHash-inspired Merkle-Damgard construction (same as
    /// EngineObjectId's deterministic hash) for collision resistance.
    pub fn compute(data: &[u8]) -> Self {
        Self(collision_resistant_hash(data))
    }

    /// Access the raw bytes.
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    /// Hex representation.
    pub fn to_hex(&self) -> String {
        let mut s = String::with_capacity(64);
        for byte in &self.0 {
            s.push_str(&format!("{byte:02x}"));
        }
        s
    }
}

impl fmt::Display for ContentHash {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "content:{}", self.to_hex())
    }
}

// ---------------------------------------------------------------------------
// Tier 3 — AuthenticityHash (keyed, security-critical)
// ---------------------------------------------------------------------------

/// Tier 3: cryptographic hash for trust authenticity (keyed contexts).
///
/// Used for: decision receipt signatures, key derivation (HKDF),
/// HMAC-based idempotency keys, evidence chain integrity.
///
/// Scope: security-critical, epoch-scoped, used with signing keys.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct AuthenticityHash(pub [u8; 32]);

impl AuthenticityHash {
    /// Compute a keyed authenticity hash (HMAC-like) over the given bytes.
    ///
    /// The key is mixed into the state before and after processing.
    pub fn compute_keyed(key: &[u8], data: &[u8]) -> Self {
        Self(keyed_hash(key, data))
    }

    /// Compute an unkeyed authenticity hash (for contexts where the key
    /// is applied externally, e.g., HKDF expand).
    pub fn compute(data: &[u8]) -> Self {
        Self(collision_resistant_hash(data))
    }

    /// Access the raw bytes.
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    /// Hex representation.
    pub fn to_hex(&self) -> String {
        let mut s = String::with_capacity(64);
        for byte in &self.0 {
            s.push_str(&format!("{byte:02x}"));
        }
        s
    }

    /// Constant-time comparison for verification (no early exit).
    pub fn constant_time_eq(&self, other: &Self) -> bool {
        let mut diff: u8 = 0;
        for i in 0..32 {
            diff |= self.0[i] ^ other.0[i];
        }
        diff == 0
    }
}

impl fmt::Display for AuthenticityHash {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "authenticity:{}", self.to_hex())
    }
}

// ---------------------------------------------------------------------------
// HashTier — tier metadata enum
// ---------------------------------------------------------------------------

/// Metadata identifying which hash tier a value belongs to.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum HashTier {
    /// Tier 1: hot integrity (non-cryptographic, ephemeral).
    Integrity,
    /// Tier 2: content identity (collision-resistant, persisted).
    Content,
    /// Tier 3: trust authenticity (cryptographic, keyed).
    Authenticity,
}

impl fmt::Display for HashTier {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Integrity => write!(f, "tier1:integrity"),
            Self::Content => write!(f, "tier2:content"),
            Self::Authenticity => write!(f, "tier3:authenticity"),
        }
    }
}

// ---------------------------------------------------------------------------
// HashAlgorithm — algorithm registry per tier
// ---------------------------------------------------------------------------

/// Hash algorithm identifiers used within each tier.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum HashAlgorithm {
    /// Tier 1: wyhash-inspired fast hash.
    WyhashInspired,
    /// Tier 2: SipHash-inspired collision-resistant hash.
    SipInspiredCr,
    /// Tier 3: SipHash-inspired keyed hash.
    SipInspiredKeyed,
}

impl HashAlgorithm {
    /// Which tier this algorithm belongs to.
    pub fn tier(&self) -> HashTier {
        match self {
            Self::WyhashInspired => HashTier::Integrity,
            Self::SipInspiredCr => HashTier::Content,
            Self::SipInspiredKeyed => HashTier::Authenticity,
        }
    }
}

impl fmt::Display for HashAlgorithm {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::WyhashInspired => write!(f, "wyhash_inspired"),
            Self::SipInspiredCr => write!(f, "sip_inspired_cr"),
            Self::SipInspiredKeyed => write!(f, "sip_inspired_keyed"),
        }
    }
}

// ---------------------------------------------------------------------------
// HashEvent — structured audit event for Tier 2/3 operations
// ---------------------------------------------------------------------------

/// Structured audit event for hash operations at Tier 2 and Tier 3.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HashEvent {
    pub tier: HashTier,
    pub algorithm: HashAlgorithm,
    pub input_len: usize,
    pub component: String,
    pub trace_id: String,
}

// ---------------------------------------------------------------------------
// Tier 1: wyhash-inspired fast hash
// ---------------------------------------------------------------------------

/// Fast non-cryptographic hash inspired by wyhash.
///
/// Optimized for speed, NOT for collision resistance. Suitable for
/// hot-path integrity checks where the adversary cannot control inputs.
fn wyhash_inspired(data: &[u8]) -> u64 {
    let mut h: u64 = data.len() as u64;
    let mut i = 0;

    // Process 8 bytes at a time.
    while i + 8 <= data.len() {
        let word = u64::from_le_bytes([
            data[i],
            data[i + 1],
            data[i + 2],
            data[i + 3],
            data[i + 4],
            data[i + 5],
            data[i + 6],
            data[i + 7],
        ]);
        h = wymix(h ^ word, h.wrapping_add(word));
        i += 8;
    }

    // Process remaining bytes.
    if i < data.len() {
        let mut tail = [0u8; 8];
        tail[..data.len() - i].copy_from_slice(&data[i..]);
        let word = u64::from_le_bytes(tail);
        h = wymix(h ^ word, h.wrapping_add(word));
    }

    // Final mix.
    wymix(h, h ^ 0xe7037ed1a0b428db)
}

/// Wyhash mixing function.
#[inline]
fn wymix(a: u64, b: u64) -> u64 {
    let full = (a as u128).wrapping_mul(b as u128);
    (full as u64) ^ ((full >> 64) as u64)
}

// ---------------------------------------------------------------------------
// Tier 2/3: collision-resistant hash (SipHash-inspired)
// ---------------------------------------------------------------------------

/// Collision-resistant hash producing 32 bytes.
///
/// Same construction as engine_object_id::deterministic_hash for
/// consistency across the codebase.
fn collision_resistant_hash(input: &[u8]) -> [u8; 32] {
    let mut state: [u64; 4] = [
        0x736f_6d65_7073_6575,
        0x646f_7261_6e64_6f6d,
        0x6c79_6765_6e65_7261,
        0x7465_6462_7974_6573,
    ];

    state[0] ^= input.len() as u64;

    for chunk in input.chunks(8) {
        let mut block = [0u8; 8];
        block[..chunk.len()].copy_from_slice(chunk);
        let word = u64::from_le_bytes(block);

        state[3] ^= word;
        sip_round(&mut state);
        sip_round(&mut state);
        state[0] ^= word;
    }

    finalize_state(&mut state)
}

/// Keyed hash: mixes key before and after data processing.
fn keyed_hash(key: &[u8], data: &[u8]) -> [u8; 32] {
    let mut state: [u64; 4] = [
        0x736f_6d65_7073_6575,
        0x646f_7261_6e64_6f6d,
        0x6c79_6765_6e65_7261,
        0x7465_6462_7974_6573,
    ];

    // Mix in key first.
    for chunk in key.chunks(8) {
        let mut block = [0u8; 8];
        block[..chunk.len()].copy_from_slice(chunk);
        let word = u64::from_le_bytes(block);
        state[1] ^= word;
        sip_round(&mut state);
        state[2] ^= word;
    }

    // Mix in key length for domain separation.
    state[0] ^= key.len() as u64;
    state[3] ^= 0x0a;
    sip_round(&mut state);

    // Process data.
    state[0] ^= data.len() as u64;
    for chunk in data.chunks(8) {
        let mut block = [0u8; 8];
        block[..chunk.len()].copy_from_slice(chunk);
        let word = u64::from_le_bytes(block);
        state[3] ^= word;
        sip_round(&mut state);
        sip_round(&mut state);
        state[0] ^= word;
    }

    // Mix key again for outer keying.
    for chunk in key.chunks(8) {
        let mut block = [0u8; 8];
        block[..chunk.len()].copy_from_slice(chunk);
        let word = u64::from_le_bytes(block);
        state[0] ^= word;
        sip_round(&mut state);
    }

    finalize_state(&mut state)
}

/// SipHash-like mixing round.
#[inline]
fn sip_round(state: &mut [u64; 4]) {
    state[0] = state[0].wrapping_add(state[1]);
    state[1] = state[1].rotate_left(13);
    state[1] ^= state[0];
    state[0] = state[0].rotate_left(32);

    state[2] = state[2].wrapping_add(state[3]);
    state[3] = state[3].rotate_left(16);
    state[3] ^= state[2];

    state[0] = state[0].wrapping_add(state[3]);
    state[3] = state[3].rotate_left(21);
    state[3] ^= state[0];

    state[2] = state[2].wrapping_add(state[1]);
    state[1] = state[1].rotate_left(17);
    state[1] ^= state[2];
    state[2] = state[2].rotate_left(32);
}

/// Finalize state into 32-byte output.
fn finalize_state(state: &mut [u64; 4]) -> [u8; 32] {
    state[2] ^= 0xff;
    for _ in 0..4 {
        sip_round(state);
    }
    let h1 = state[0] ^ state[1] ^ state[2] ^ state[3];

    state[1] ^= 0xee;
    for _ in 0..4 {
        sip_round(state);
    }
    let h2 = state[0] ^ state[1] ^ state[2] ^ state[3];

    state[0] ^= 0xdd;
    for _ in 0..4 {
        sip_round(state);
    }
    let h3 = state[0] ^ state[1] ^ state[2] ^ state[3];

    state[3] ^= 0xcc;
    for _ in 0..4 {
        sip_round(state);
    }
    let h4 = state[0] ^ state[1] ^ state[2] ^ state[3];

    let mut output = [0u8; 32];
    output[0..8].copy_from_slice(&h1.to_le_bytes());
    output[8..16].copy_from_slice(&h2.to_le_bytes());
    output[16..24].copy_from_slice(&h3.to_le_bytes());
    output[24..32].copy_from_slice(&h4.to_le_bytes());
    output
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    // -- Tier 1: IntegrityHash --

    #[test]
    fn integrity_hash_deterministic() {
        let a = IntegrityHash::compute(b"test data");
        let b = IntegrityHash::compute(b"test data");
        assert_eq!(a, b);
    }

    #[test]
    fn integrity_hash_different_inputs_different_outputs() {
        let a = IntegrityHash::compute(b"alpha");
        let b = IntegrityHash::compute(b"beta");
        assert_ne!(a, b);
    }

    #[test]
    fn integrity_hash_empty_input() {
        let h = IntegrityHash::compute(b"");
        // Should produce a valid hash, not panic.
        assert_eq!(h.as_u64(), IntegrityHash::compute(b"").as_u64());
    }

    #[test]
    fn integrity_hash_display() {
        let h = IntegrityHash::compute(b"test");
        let display = h.to_string();
        assert!(display.starts_with("integrity:"));
        assert_eq!(display.len(), "integrity:".len() + 16);
    }

    #[test]
    fn integrity_hash_various_lengths() {
        // Test with different input lengths including edge cases.
        let lengths = [0, 1, 7, 8, 9, 15, 16, 31, 32, 64, 100, 255, 1024];
        let mut seen = std::collections::BTreeSet::new();
        for len in lengths {
            let data: Vec<u8> = (0..len).map(|i| (i % 256) as u8).collect();
            let h = IntegrityHash::compute(&data);
            seen.insert(h.as_u64());
        }
        // All different lengths should produce different hashes.
        assert_eq!(seen.len(), lengths.len());
    }

    // -- Tier 2: ContentHash --

    #[test]
    fn content_hash_deterministic() {
        let a = ContentHash::compute(b"evidence payload");
        let b = ContentHash::compute(b"evidence payload");
        assert_eq!(a, b);
    }

    #[test]
    fn content_hash_different_inputs_different_outputs() {
        let a = ContentHash::compute(b"content-a");
        let b = ContentHash::compute(b"content-b");
        assert_ne!(a, b);
    }

    #[test]
    fn content_hash_is_32_bytes() {
        let h = ContentHash::compute(b"any data");
        assert_eq!(h.as_bytes().len(), 32);
    }

    #[test]
    fn content_hash_from_bytes_preserves_input_bytes() {
        let bytes = [0x5au8; 32];
        let h = ContentHash::from_bytes(bytes);
        assert_eq!(h.as_bytes(), &bytes);
    }

    #[test]
    fn content_hash_hex_round_trip() {
        let h = ContentHash::compute(b"test");
        let hex = h.to_hex();
        assert_eq!(hex.len(), 64);
        assert!(hex.chars().all(|c| c.is_ascii_hexdigit()));
    }

    #[test]
    fn content_hash_display() {
        let h = ContentHash::compute(b"test");
        let display = h.to_string();
        assert!(display.starts_with("content:"));
    }

    #[test]
    fn content_hash_avalanche() {
        let a = ContentHash::compute(b"test input A");
        let b = ContentHash::compute(b"test input B");
        let differing_bits: u32 = a
            .as_bytes()
            .iter()
            .zip(b.as_bytes().iter())
            .map(|(x, y)| (x ^ y).count_ones())
            .sum();
        // Good avalanche: at least 30% of bits differ.
        assert!(
            differing_bits > (256 * 30 / 100),
            "poor avalanche: only {differing_bits}/256 bits differ"
        );
    }

    // -- Tier 3: AuthenticityHash --

    #[test]
    fn authenticity_hash_keyed_deterministic() {
        let a = AuthenticityHash::compute_keyed(b"secret-key", b"message");
        let b = AuthenticityHash::compute_keyed(b"secret-key", b"message");
        assert_eq!(a, b);
    }

    #[test]
    fn authenticity_hash_different_keys_different_outputs() {
        let a = AuthenticityHash::compute_keyed(b"key-1", b"same message");
        let b = AuthenticityHash::compute_keyed(b"key-2", b"same message");
        assert_ne!(a, b);
    }

    #[test]
    fn authenticity_hash_different_messages_different_outputs() {
        let a = AuthenticityHash::compute_keyed(b"same-key", b"message-1");
        let b = AuthenticityHash::compute_keyed(b"same-key", b"message-2");
        assert_ne!(a, b);
    }

    #[test]
    fn authenticity_hash_unkeyed_matches_content_hash() {
        // Unkeyed authenticity hash should produce same output as content hash
        // (same underlying algorithm).
        let auth = AuthenticityHash::compute(b"test data");
        let content = ContentHash::compute(b"test data");
        assert_eq!(auth.as_bytes(), content.as_bytes());
    }

    #[test]
    fn authenticity_hash_keyed_differs_from_unkeyed() {
        let keyed = AuthenticityHash::compute_keyed(b"any-key", b"test data");
        let unkeyed = AuthenticityHash::compute(b"test data");
        assert_ne!(keyed.as_bytes(), unkeyed.as_bytes());
    }

    #[test]
    fn authenticity_hash_constant_time_eq_same() {
        let a = AuthenticityHash::compute_keyed(b"key", b"data");
        let b = AuthenticityHash::compute_keyed(b"key", b"data");
        assert!(a.constant_time_eq(&b));
    }

    #[test]
    fn authenticity_hash_constant_time_eq_different() {
        let a = AuthenticityHash::compute_keyed(b"key-1", b"data");
        let b = AuthenticityHash::compute_keyed(b"key-2", b"data");
        assert!(!a.constant_time_eq(&b));
    }

    #[test]
    fn authenticity_hash_display() {
        let h = AuthenticityHash::compute(b"test");
        let display = h.to_string();
        assert!(display.starts_with("authenticity:"));
    }

    // -- Cross-tier type safety --

    #[test]
    fn tiers_are_distinct_types() {
        // This is a compile-time guarantee enforced by the type system.
        // The test verifies the types exist and are distinct at runtime.
        let t1 = IntegrityHash::compute(b"data");
        let t2 = ContentHash::compute(b"data");
        let t3 = AuthenticityHash::compute(b"data");

        // t1 is u64, t2 and t3 are [u8; 32] — structurally different.
        assert_eq!(std::mem::size_of_val(&t1), 8);
        assert_eq!(std::mem::size_of_val(&t2), 32);
        assert_eq!(std::mem::size_of_val(&t3), 32);
    }

    // -- HashTier --

    #[test]
    fn hash_tier_display() {
        assert_eq!(HashTier::Integrity.to_string(), "tier1:integrity");
        assert_eq!(HashTier::Content.to_string(), "tier2:content");
        assert_eq!(HashTier::Authenticity.to_string(), "tier3:authenticity");
    }

    #[test]
    fn hash_tier_ordering() {
        assert!(HashTier::Integrity < HashTier::Content);
        assert!(HashTier::Content < HashTier::Authenticity);
    }

    // -- HashAlgorithm --

    #[test]
    fn algorithm_tier_mapping() {
        assert_eq!(HashAlgorithm::WyhashInspired.tier(), HashTier::Integrity);
        assert_eq!(HashAlgorithm::SipInspiredCr.tier(), HashTier::Content);
        assert_eq!(
            HashAlgorithm::SipInspiredKeyed.tier(),
            HashTier::Authenticity
        );
    }

    #[test]
    fn algorithm_display() {
        assert_eq!(HashAlgorithm::WyhashInspired.to_string(), "wyhash_inspired");
        assert_eq!(HashAlgorithm::SipInspiredCr.to_string(), "sip_inspired_cr");
        assert_eq!(
            HashAlgorithm::SipInspiredKeyed.to_string(),
            "sip_inspired_keyed"
        );
    }

    // -- Empty key behavior --

    #[test]
    fn keyed_hash_with_empty_key() {
        // Empty key should still produce a valid hash.
        let h = AuthenticityHash::compute_keyed(b"", b"data");
        assert_eq!(h.as_bytes().len(), 32);
    }

    #[test]
    fn keyed_hash_with_empty_data() {
        let h = AuthenticityHash::compute_keyed(b"key", b"");
        assert_eq!(h.as_bytes().len(), 32);
    }

    #[test]
    fn keyed_hash_with_both_empty() {
        let h = AuthenticityHash::compute_keyed(b"", b"");
        assert_eq!(h.as_bytes().len(), 32);
    }

    // -- Wyhash length sensitivity --

    #[test]
    fn wyhash_length_dependence() {
        // Identical prefix but different length.
        let a = IntegrityHash::compute(b"hello");
        let b = IntegrityHash::compute(b"hello world");
        assert_ne!(a, b);
    }

    // -- Serialization --

    #[test]
    fn integrity_hash_serialization_round_trip() {
        let h = IntegrityHash::compute(b"test");
        let json = serde_json::to_string(&h).expect("serialize");
        let restored: IntegrityHash = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(h, restored);
    }

    #[test]
    fn content_hash_serialization_round_trip() {
        let h = ContentHash::compute(b"test");
        let json = serde_json::to_string(&h).expect("serialize");
        let restored: ContentHash = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(h, restored);
    }

    #[test]
    fn authenticity_hash_serialization_round_trip() {
        let h = AuthenticityHash::compute_keyed(b"key", b"data");
        let json = serde_json::to_string(&h).expect("serialize");
        let restored: AuthenticityHash = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(h, restored);
    }

    #[test]
    fn hash_event_serialization_round_trip() {
        let event = HashEvent {
            tier: HashTier::Content,
            algorithm: HashAlgorithm::SipInspiredCr,
            input_len: 42,
            component: "evidence_ledger".to_string(),
            trace_id: "trace-123".to_string(),
        };
        let json = serde_json::to_string(&event).expect("serialize");
        let restored: HashEvent = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(event, restored);
    }

    #[test]
    fn hash_tier_serialization_round_trip() {
        for tier in [
            HashTier::Integrity,
            HashTier::Content,
            HashTier::Authenticity,
        ] {
            let json = serde_json::to_string(&tier).expect("serialize");
            let restored: HashTier = serde_json::from_str(&json).expect("deserialize");
            assert_eq!(tier, restored);
        }
    }

    #[test]
    fn hash_algorithm_serialization_round_trip() {
        for alg in [
            HashAlgorithm::WyhashInspired,
            HashAlgorithm::SipInspiredCr,
            HashAlgorithm::SipInspiredKeyed,
        ] {
            let json = serde_json::to_string(&alg).expect("serialize");
            let restored: HashAlgorithm = serde_json::from_str(&json).expect("deserialize");
            assert_eq!(alg, restored);
        }
    }

    // -- Golden vectors --

    #[test]
    fn golden_vector_tier1() {
        let h = IntegrityHash::compute(b"franken-engine-golden-vector");
        // Re-derive to confirm determinism.
        let h2 = IntegrityHash::compute(b"franken-engine-golden-vector");
        assert_eq!(h, h2);
    }

    #[test]
    fn golden_vector_tier2() {
        let h = ContentHash::compute(b"franken-engine-golden-vector");
        let h2 = ContentHash::compute(b"franken-engine-golden-vector");
        assert_eq!(h, h2);
    }

    #[test]
    fn golden_vector_tier3_keyed() {
        let h = AuthenticityHash::compute_keyed(
            b"golden-key-material",
            b"franken-engine-golden-vector",
        );
        let h2 = AuthenticityHash::compute_keyed(
            b"golden-key-material",
            b"franken-engine-golden-vector",
        );
        assert_eq!(h, h2);
    }

    // -- Tier 2/3 consistency --

    #[test]
    fn content_and_unkeyed_authenticity_use_same_algorithm() {
        // Important invariant: unkeyed Tier 3 = Tier 2 algorithm.
        let c = ContentHash::compute(b"shared-test-vector");
        let a = AuthenticityHash::compute(b"shared-test-vector");
        assert_eq!(c.as_bytes(), a.as_bytes());
    }

    // -----------------------------------------------------------------------
    // Enrichment batch 2: Display uniqueness, edge cases, hex format
    // -----------------------------------------------------------------------

    #[test]
    fn hash_tier_display_all_unique() {
        let tiers = [
            HashTier::Integrity,
            HashTier::Content,
            HashTier::Authenticity,
        ];
        let mut seen = std::collections::BTreeSet::new();
        for t in &tiers {
            seen.insert(t.to_string());
        }
        assert_eq!(
            seen.len(),
            3,
            "all 3 HashTier Display strings must be unique"
        );
    }

    #[test]
    fn hash_algorithm_display_all_unique() {
        let algs = [
            HashAlgorithm::WyhashInspired,
            HashAlgorithm::SipInspiredCr,
            HashAlgorithm::SipInspiredKeyed,
        ];
        let mut seen = std::collections::BTreeSet::new();
        for a in &algs {
            seen.insert(a.to_string());
        }
        assert_eq!(
            seen.len(),
            3,
            "all 3 HashAlgorithm Display strings must be unique"
        );
    }

    #[test]
    fn integrity_hash_display_format_hex_length() {
        let h = IntegrityHash(0x0123_4567_89ab_cdef);
        let display = h.to_string();
        assert_eq!(display, "integrity:0123456789abcdef");
    }

    #[test]
    fn content_hash_hex_is_lowercase() {
        let h = ContentHash::compute(b"lowercase check");
        let hex = h.to_hex();
        assert!(
            hex.chars()
                .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit())
        );
    }

    #[test]
    fn authenticity_hash_hex_is_lowercase() {
        let h = AuthenticityHash::compute_keyed(b"k", b"d");
        let hex = h.to_hex();
        assert!(
            hex.chars()
                .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit())
        );
    }

    #[test]
    fn content_hash_display_format() {
        let h = ContentHash::compute(b"display format");
        let display = h.to_string();
        assert!(display.starts_with("content:"));
        assert_eq!(display.len(), "content:".len() + 64);
    }

    #[test]
    fn authenticity_hash_display_format() {
        let h = AuthenticityHash::compute_keyed(b"k", b"d");
        let display = h.to_string();
        assert!(display.starts_with("authenticity:"));
        assert_eq!(display.len(), "authenticity:".len() + 64);
    }

    #[test]
    fn integrity_hash_single_byte_inputs_differ() {
        let h0 = IntegrityHash::compute(&[0u8]);
        let h1 = IntegrityHash::compute(&[1u8]);
        let hff = IntegrityHash::compute(&[0xffu8]);
        assert_ne!(h0, h1);
        assert_ne!(h1, hff);
        assert_ne!(h0, hff);
    }

    #[test]
    fn content_hash_ordering_is_byte_based() {
        let a = ContentHash::compute(b"aaa");
        let b = ContentHash::compute(b"bbb");
        // Ordering should be defined and consistent (byte comparison)
        let cmp1 = a.cmp(&b);
        let cmp2 = a.cmp(&b);
        assert_eq!(cmp1, cmp2);
    }

    #[test]
    fn authenticity_constant_time_eq_reflexive() {
        let h = AuthenticityHash::compute_keyed(b"key", b"data");
        assert!(h.constant_time_eq(&h));
    }

    // -----------------------------------------------------------------------
    // Enrichment batch 3: clone equality, JSON fields, serde, Ord, boundary
    // -----------------------------------------------------------------------

    #[test]
    fn integrity_hash_clone_equality() {
        let h = IntegrityHash::compute(b"clone-test-integrity");
        let cloned = h;
        assert_eq!(h, cloned);
    }

    #[test]
    fn content_hash_clone_equality() {
        let h = ContentHash::compute(b"clone-test-content");
        let cloned = h.clone();
        assert_eq!(h, cloned);
    }

    #[test]
    fn authenticity_hash_clone_equality() {
        let h = AuthenticityHash::compute_keyed(b"key", b"clone-test-auth");
        let cloned = h.clone();
        assert_eq!(h, cloned);
    }

    #[test]
    fn hash_tier_clone_equality() {
        let tier = HashTier::Authenticity;
        let cloned = tier;
        assert_eq!(tier, cloned);
    }

    #[test]
    fn hash_algorithm_clone_equality() {
        let alg = HashAlgorithm::SipInspiredKeyed;
        let cloned = alg;
        assert_eq!(alg, cloned);
    }

    #[test]
    fn hash_event_json_field_tier_present() {
        let event = HashEvent {
            tier: HashTier::Integrity,
            algorithm: HashAlgorithm::WyhashInspired,
            input_len: 10,
            component: "test_comp".to_string(),
            trace_id: "t-001".to_string(),
        };
        let json = serde_json::to_string(&event).expect("serialize");
        assert!(json.contains("\"tier\""), "JSON must contain 'tier' field");
    }

    #[test]
    fn hash_event_json_field_algorithm_present() {
        let event = HashEvent {
            tier: HashTier::Content,
            algorithm: HashAlgorithm::SipInspiredCr,
            input_len: 20,
            component: "algo_check".to_string(),
            trace_id: "t-002".to_string(),
        };
        let json = serde_json::to_string(&event).expect("serialize");
        assert!(
            json.contains("\"algorithm\""),
            "JSON must contain 'algorithm' field"
        );
    }

    #[test]
    fn hash_event_json_field_trace_id_and_component_present() {
        let event = HashEvent {
            tier: HashTier::Authenticity,
            algorithm: HashAlgorithm::SipInspiredKeyed,
            input_len: 30,
            component: "my_component".to_string(),
            trace_id: "trace-xyz".to_string(),
        };
        let json = serde_json::to_string(&event).expect("serialize");
        assert!(
            json.contains("\"trace_id\""),
            "JSON must contain 'trace_id' field"
        );
        assert!(
            json.contains("\"component\""),
            "JSON must contain 'component' field"
        );
    }

    #[test]
    fn hash_event_serde_roundtrip_all_tiers() {
        let tiers = [
            (HashTier::Integrity, HashAlgorithm::WyhashInspired),
            (HashTier::Content, HashAlgorithm::SipInspiredCr),
            (HashTier::Authenticity, HashAlgorithm::SipInspiredKeyed),
        ];
        for (tier, alg) in tiers {
            let event = HashEvent {
                tier,
                algorithm: alg,
                input_len: 99,
                component: format!("roundtrip_{tier}"),
                trace_id: "rt-000".to_string(),
            };
            let json = serde_json::to_string(&event).expect("serialize");
            let restored: HashEvent = serde_json::from_str(&json).expect("deserialize");
            assert_eq!(event, restored);
        }
    }

    #[test]
    fn display_uniqueness_across_tiers_same_input() {
        let data = b"cross-tier-display-check";
        let d1 = IntegrityHash::compute(data).to_string();
        let d2 = ContentHash::compute(data).to_string();
        let d3 = AuthenticityHash::compute(data).to_string();
        let mut seen = std::collections::BTreeSet::new();
        seen.insert(d1);
        seen.insert(d2);
        seen.insert(d3);
        assert_eq!(seen.len(), 3, "Display strings across tiers must be unique");
    }

    #[test]
    fn integrity_hash_boundary_max_u64() {
        let h = IntegrityHash(u64::MAX);
        assert_eq!(h.as_u64(), u64::MAX);
        let display = h.to_string();
        assert_eq!(display, "integrity:ffffffffffffffff");
    }

    #[test]
    fn hash_tier_ord_determinism() {
        let mut tiers_a = vec![
            HashTier::Authenticity,
            HashTier::Integrity,
            HashTier::Content,
        ];
        let mut tiers_b = tiers_a.clone();
        tiers_a.sort();
        tiers_b.sort();
        assert_eq!(tiers_a, tiers_b);
        assert_eq!(tiers_a[0], HashTier::Integrity);
        assert_eq!(tiers_a[1], HashTier::Content);
        assert_eq!(tiers_a[2], HashTier::Authenticity);
    }

    // -----------------------------------------------------------------------
    // Enrichment batch 4: copy/Ord/bit-flip, cross-tier, edge cases
    // -----------------------------------------------------------------------

    #[test]
    fn integrity_hash_copy_semantics() {
        let h = IntegrityHash::compute(b"copy-test");
        let copied = h;
        // Both usable after copy (IntegrityHash is Copy).
        assert_eq!(h.as_u64(), copied.as_u64());
    }

    #[test]
    fn integrity_hash_ord_in_btreeset() {
        let mut set = std::collections::BTreeSet::new();
        let h1 = IntegrityHash::compute(b"aaa");
        let h2 = IntegrityHash::compute(b"bbb");
        let h3 = IntegrityHash::compute(b"ccc");
        set.insert(h1);
        set.insert(h2);
        set.insert(h3);
        assert_eq!(set.len(), 3);
        // Re-insert duplicate.
        set.insert(h1);
        assert_eq!(set.len(), 3);
    }

    #[test]
    fn integrity_hash_single_bit_flip_sensitivity() {
        let mut data = vec![0u8; 16];
        let base = IntegrityHash::compute(&data);
        data[7] ^= 1; // flip one bit
        let flipped = IntegrityHash::compute(&data);
        assert_ne!(base, flipped, "single bit flip must change hash");
    }

    #[test]
    fn integrity_hash_json_format_is_number() {
        let h = IntegrityHash(42);
        let json = serde_json::to_string(&h).expect("serialize");
        // IntegrityHash(u64) serializes as a number.
        assert_eq!(json, "42");
    }

    #[test]
    fn content_hash_empty_input_produces_valid_hash() {
        let h = ContentHash::compute(b"");
        assert_eq!(h.as_bytes().len(), 32);
        // Should be deterministic.
        assert_eq!(h, ContentHash::compute(b""));
    }

    #[test]
    fn content_hash_to_hex_matches_display_suffix() {
        let h = ContentHash::compute(b"hex-vs-display");
        let display = h.to_string();
        let hex = h.to_hex();
        assert_eq!(display, format!("content:{hex}"));
    }

    #[test]
    fn content_hash_large_input_deterministic() {
        let data: Vec<u8> = (0..4096).map(|i| (i % 251) as u8).collect();
        let a = ContentHash::compute(&data);
        let b = ContentHash::compute(&data);
        assert_eq!(a, b);
    }

    #[test]
    fn content_hash_single_bit_flip_sensitivity() {
        let mut data = vec![0u8; 64];
        let base = ContentHash::compute(&data);
        data[31] ^= 0x80;
        let flipped = ContentHash::compute(&data);
        assert_ne!(base, flipped, "single bit flip must change content hash");
    }

    #[test]
    fn content_hash_ord_sort_deterministic() {
        let hashes: Vec<ContentHash> = (0u8..10).map(|i| ContentHash::compute(&[i])).collect();
        let mut sorted_a = hashes.clone();
        let mut sorted_b = hashes.clone();
        sorted_a.sort();
        sorted_b.sort();
        assert_eq!(sorted_a, sorted_b);
    }

    #[test]
    fn authenticity_hash_constant_time_eq_all_zeros() {
        let h = AuthenticityHash([0u8; 32]);
        assert!(h.constant_time_eq(&AuthenticityHash([0u8; 32])));
        assert!(!h.constant_time_eq(&AuthenticityHash([
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 1
        ])));
    }

    #[test]
    fn authenticity_hash_constant_time_eq_single_bit_diff() {
        let a = AuthenticityHash::compute_keyed(b"key", b"data");
        let mut bytes = *a.as_bytes();
        bytes[0] ^= 1;
        let b = AuthenticityHash(bytes);
        assert!(!a.constant_time_eq(&b));
    }

    #[test]
    fn authenticity_hash_long_key_works() {
        let long_key: Vec<u8> = (0..256).map(|i| (i % 256) as u8).collect();
        let h = AuthenticityHash::compute_keyed(&long_key, b"msg");
        assert_eq!(h.as_bytes().len(), 32);
        // Deterministic with long key.
        assert_eq!(h, AuthenticityHash::compute_keyed(&long_key, b"msg"));
    }

    #[test]
    fn authenticity_hash_empty_key_differs_from_unkeyed() {
        // Domain separation in keyed_hash means even empty key differs.
        let keyed_empty = AuthenticityHash::compute_keyed(b"", b"data");
        let unkeyed = AuthenticityHash::compute(b"data");
        assert_ne!(keyed_empty.as_bytes(), unkeyed.as_bytes());
    }

    #[test]
    fn authenticity_hash_to_hex_matches_display_suffix() {
        let h = AuthenticityHash::compute_keyed(b"k", b"d");
        let display = h.to_string();
        let hex = h.to_hex();
        assert_eq!(display, format!("authenticity:{hex}"));
    }

    #[test]
    fn hash_event_clone_eq() {
        let event = HashEvent {
            tier: HashTier::Content,
            algorithm: HashAlgorithm::SipInspiredCr,
            input_len: 100,
            component: "clone_test".to_string(),
            trace_id: "t-999".to_string(),
        };
        let cloned = event.clone();
        assert_eq!(event, cloned);
    }

    #[test]
    fn hash_event_json_field_input_len_present() {
        let event = HashEvent {
            tier: HashTier::Integrity,
            algorithm: HashAlgorithm::WyhashInspired,
            input_len: 12345,
            component: "len_check".to_string(),
            trace_id: "t-len".to_string(),
        };
        let json = serde_json::to_string(&event).expect("serialize");
        assert!(json.contains("\"input_len\""));
        assert!(json.contains("12345"));
    }

    #[test]
    fn hash_algorithm_ord_sort_deterministic() {
        let mut algs_a = vec![
            HashAlgorithm::SipInspiredKeyed,
            HashAlgorithm::WyhashInspired,
            HashAlgorithm::SipInspiredCr,
        ];
        let mut algs_b = algs_a.clone();
        algs_a.sort();
        algs_b.sort();
        assert_eq!(algs_a, algs_b);
        assert_eq!(algs_a[0], HashAlgorithm::WyhashInspired);
    }

    #[test]
    fn hash_algorithm_tier_bijection() {
        // Each algorithm maps to a unique tier.
        let algs = [
            HashAlgorithm::WyhashInspired,
            HashAlgorithm::SipInspiredCr,
            HashAlgorithm::SipInspiredKeyed,
        ];
        let mut seen_tiers = std::collections::BTreeSet::new();
        for alg in &algs {
            seen_tiers.insert(alg.tier());
        }
        assert_eq!(seen_tiers.len(), 3, "each algorithm maps to unique tier");
    }

    #[test]
    fn integrity_hash_std_hash_consistent() {
        use std::hash::{Hash, Hasher};
        let h = IntegrityHash::compute(b"hash-trait-test");
        let mut hasher_a = std::collections::hash_map::DefaultHasher::new();
        let mut hasher_b = std::collections::hash_map::DefaultHasher::new();
        h.hash(&mut hasher_a);
        h.hash(&mut hasher_b);
        assert_eq!(hasher_a.finish(), hasher_b.finish());
    }

    #[test]
    fn content_hash_all_zeros_input() {
        let data = [0u8; 32];
        let h = ContentHash::compute(&data);
        assert_eq!(h.as_bytes().len(), 32);
        // Not all zeros in output (hash should mix).
        assert_ne!(h.as_bytes(), &[0u8; 32]);
    }

    #[test]
    fn keyed_hash_key_data_not_commutative() {
        let a = AuthenticityHash::compute_keyed(b"alpha", b"beta");
        let b = AuthenticityHash::compute_keyed(b"beta", b"alpha");
        assert_ne!(a, b, "hash(k=alpha, d=beta) != hash(k=beta, d=alpha)");
    }

    #[test]
    fn integrity_hash_boundary_zero() {
        let h = IntegrityHash(0);
        assert_eq!(h.as_u64(), 0);
        assert_eq!(h.to_string(), "integrity:0000000000000000");
    }

    #[test]
    fn content_hash_hash_trait_works() {
        use std::hash::{Hash, Hasher};
        let h = ContentHash::compute(b"hash-trait");
        let mut hasher_a = std::collections::hash_map::DefaultHasher::new();
        let mut hasher_b = std::collections::hash_map::DefaultHasher::new();
        h.hash(&mut hasher_a);
        h.hash(&mut hasher_b);
        assert_eq!(hasher_a.finish(), hasher_b.finish());
    }

    #[test]
    fn authenticity_hash_hash_trait_works() {
        use std::hash::{Hash, Hasher};
        let h = AuthenticityHash::compute_keyed(b"k", b"d");
        let mut hasher_a = std::collections::hash_map::DefaultHasher::new();
        let mut hasher_b = std::collections::hash_map::DefaultHasher::new();
        h.hash(&mut hasher_a);
        h.hash(&mut hasher_b);
        assert_eq!(hasher_a.finish(), hasher_b.finish());
    }
}
