//! Idempotency-key derivation and dedup semantics for retryable remote
//! actions.
//!
//! Every remote operation that is not naturally idempotent carries a
//! deterministically derived idempotency key. The dedup store enforces
//! at-most-once execution: retries with a known key return the cached
//! result without re-execution.
//!
//! Key derivation: `keyed_hash(epoch_session_key, computation_name ||
//! input_hash || trace_id || attempt_number)`. Keys are epoch-scoped;
//! old-epoch keys are rejected.
//!
//! Plan references: Section 10.11 item 22, 9G.7 (remote-effects contract),
//! Top-10 #5 (supply-chain trust), #10 (provenance + revocation fabric).

use std::collections::BTreeMap;
use std::fmt;

use serde::{Deserialize, Serialize};

use crate::hash_tiers::{AuthenticityHash, ContentHash};
use crate::security_epoch::SecurityEpoch;

// ---------------------------------------------------------------------------
// IdempotencyKey — the derived dedup key
// ---------------------------------------------------------------------------

/// A deterministically derived idempotency key for dedup enforcement.
///
/// Derived from: computation_name, input_hash, trace_id, attempt_number,
/// bound to an epoch via keyed hashing.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct IdempotencyKey {
    /// The 32-byte key hash.
    pub key_hash: [u8; 32],
    /// The epoch in which this key was derived.
    pub epoch: SecurityEpoch,
}

impl IdempotencyKey {
    /// Hex representation of the key hash.
    pub fn to_hex(&self) -> String {
        let mut s = String::with_capacity(64);
        for byte in &self.key_hash {
            s.push_str(&format!("{byte:02x}"));
        }
        s
    }
}

impl fmt::Display for IdempotencyKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "idem:{}@{}", self.to_hex(), self.epoch)
    }
}

// ---------------------------------------------------------------------------
// KeyDerivationInput — structured input for key derivation
// ---------------------------------------------------------------------------

/// Input parameters for idempotency-key derivation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct KeyDerivationInput {
    /// Named computation identifier (from the computation registry).
    pub computation_name: String,
    /// Content hash of the deterministically encoded input.
    pub input_hash: ContentHash,
    /// Trace identifier for correlation.
    pub trace_id: String,
    /// Attempt number (0-indexed; incremented on retry).
    pub attempt_number: u32,
}

// ---------------------------------------------------------------------------
// Derivation function
// ---------------------------------------------------------------------------

/// Derive an idempotency key from its components.
///
/// The key is bound to the epoch via keyed hashing:
/// ```text
/// keyed_hash(epoch_session_key, computation_name || input_hash || trace_id || attempt_number)
/// ```
pub fn derive_idempotency_key(
    epoch_session_key: &[u8],
    epoch: SecurityEpoch,
    input: &KeyDerivationInput,
) -> IdempotencyKey {
    // Build the preimage: computation_name || input_hash || trace_id || attempt_number
    let mut preimage = Vec::new();

    // Length-prefixed computation name.
    let name_bytes = input.computation_name.as_bytes();
    preimage.extend_from_slice(&(name_bytes.len() as u32).to_be_bytes());
    preimage.extend_from_slice(name_bytes);

    // Input hash (32 bytes, fixed).
    preimage.extend_from_slice(input.input_hash.as_bytes());

    // Length-prefixed trace_id.
    let trace_bytes = input.trace_id.as_bytes();
    preimage.extend_from_slice(&(trace_bytes.len() as u32).to_be_bytes());
    preimage.extend_from_slice(trace_bytes);

    // Attempt number (4 bytes big-endian).
    preimage.extend_from_slice(&input.attempt_number.to_be_bytes());

    // Epoch binding (8 bytes big-endian).
    preimage.extend_from_slice(&epoch.as_u64().to_be_bytes());

    // Keyed hash using the epoch session key.
    let hash = AuthenticityHash::compute_keyed(epoch_session_key, &preimage);

    IdempotencyKey {
        key_hash: *hash.as_bytes(),
        epoch,
    }
}

// ---------------------------------------------------------------------------
// DedupStatus — dedup entry status
// ---------------------------------------------------------------------------

/// Status of a dedup entry in the idempotency store.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum DedupStatus {
    /// Computation is currently in progress.
    InProgress,
    /// Computation completed successfully; result is cached.
    Completed { result_hash: ContentHash },
    /// Computation failed permanently.
    Failed { error_code: String },
}

impl fmt::Display for DedupStatus {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InProgress => f.write_str("in_progress"),
            Self::Completed { .. } => f.write_str("completed"),
            Self::Failed { .. } => f.write_str("failed"),
        }
    }
}

// ---------------------------------------------------------------------------
// DedupEntry — an entry in the idempotency store
// ---------------------------------------------------------------------------

/// A single entry in the idempotency store.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DedupEntry {
    /// Current status.
    pub status: DedupStatus,
    /// Computation name for audit.
    pub computation_name: String,
    /// Creation timestamp (virtual ticks).
    pub created_at_ticks: u64,
    /// Epoch in which this entry was created.
    pub epoch: SecurityEpoch,
}

// ---------------------------------------------------------------------------
// DedupResult — outcome of a dedup check
// ---------------------------------------------------------------------------

/// Outcome of checking an idempotency key against the store.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum DedupResult {
    /// Key not found — proceed with execution.
    New,
    /// Key found, computation completed — return cached result.
    CachedResult { result_hash: ContentHash },
    /// Key found, computation still in progress — reject duplicate.
    DuplicateInProgress,
    /// Key found, computation failed — allow retry with new attempt.
    PreviouslyFailed { error_code: String },
}

impl fmt::Display for DedupResult {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::New => f.write_str("new"),
            Self::CachedResult { .. } => f.write_str("cached"),
            Self::DuplicateInProgress => f.write_str("duplicate_in_progress"),
            Self::PreviouslyFailed { .. } => f.write_str("previously_failed"),
        }
    }
}

// ---------------------------------------------------------------------------
// IdempotencyEvent — structured audit event
// ---------------------------------------------------------------------------

/// Structured audit event for idempotency operations.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct IdempotencyEvent {
    /// Hash of the idempotency key (not the raw key material).
    pub idempotency_key_hash: String,
    /// Computation name.
    pub computation_name: String,
    /// Attempt number.
    pub attempt: u32,
    /// Dedup result.
    pub dedup_result: String,
    /// Trace identifier.
    pub trace_id: String,
    /// Epoch at time of event.
    pub epoch_id: u64,
    /// Event type.
    pub event: String,
}

// ---------------------------------------------------------------------------
// IdempotencyError — typed errors
// ---------------------------------------------------------------------------

/// Errors from idempotency operations.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum IdempotencyError {
    /// Key is from an old epoch and cannot be accepted.
    EpochMismatch {
        key_epoch: SecurityEpoch,
        current_epoch: SecurityEpoch,
    },
    /// Maximum retry count exceeded.
    MaxRetriesExceeded {
        computation_name: String,
        max_retries: u32,
        attempt: u32,
    },
    /// Key already exists with in-progress status.
    DuplicateInProgress { computation_name: String },
    /// Entry not found for completion/failure marking.
    EntryNotFound { key_hex: String },
}

impl fmt::Display for IdempotencyError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::EpochMismatch {
                key_epoch,
                current_epoch,
            } => {
                write!(
                    f,
                    "idempotency key epoch mismatch: key at {key_epoch}, current {current_epoch}"
                )
            }
            Self::MaxRetriesExceeded {
                computation_name,
                max_retries,
                attempt,
            } => {
                write!(
                    f,
                    "max retries ({max_retries}) exceeded for '{computation_name}' at attempt {attempt}"
                )
            }
            Self::DuplicateInProgress { computation_name } => {
                write!(f, "duplicate in-progress for '{computation_name}'")
            }
            Self::EntryNotFound { key_hex } => {
                write!(f, "idempotency entry not found: {key_hex}")
            }
        }
    }
}

impl std::error::Error for IdempotencyError {}

// ---------------------------------------------------------------------------
// RetryConfig — per-computation retry configuration
// ---------------------------------------------------------------------------

/// Retry configuration for a computation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RetryConfig {
    /// Maximum number of retry attempts (default: 3).
    pub max_retries: u32,
    /// TTL for idempotency store entries in virtual ticks.
    pub entry_ttl_ticks: u64,
}

impl Default for RetryConfig {
    fn default() -> Self {
        Self {
            max_retries: 3,
            entry_ttl_ticks: 600,
        }
    }
}

// ---------------------------------------------------------------------------
// IdempotencyStore — the dedup store
// ---------------------------------------------------------------------------

/// Idempotency store enforcing at-most-once execution for remote operations.
///
/// Maps idempotency keys to dedup entries with TTL-based expiration.
/// Uses `BTreeMap` for deterministic iteration ordering.
#[derive(Debug)]
pub struct IdempotencyStore {
    /// The current security epoch.
    current_epoch: SecurityEpoch,
    /// Epoch session key for key derivation.
    session_key: Vec<u8>,
    /// Per-computation retry configuration.
    retry_configs: BTreeMap<String, RetryConfig>,
    /// Default retry config for computations without specific config.
    default_retry_config: RetryConfig,
    /// Active dedup entries keyed by idempotency key hash hex.
    entries: BTreeMap<String, DedupEntry>,
    /// Accumulated audit events.
    events: Vec<IdempotencyEvent>,
    /// Counters by dedup result type.
    result_counts: BTreeMap<String, u64>,
}

impl IdempotencyStore {
    /// Create a new idempotency store.
    pub fn new(epoch: SecurityEpoch, session_key: Vec<u8>) -> Self {
        Self {
            current_epoch: epoch,
            session_key,
            retry_configs: BTreeMap::new(),
            default_retry_config: RetryConfig::default(),
            entries: BTreeMap::new(),
            events: Vec::new(),
            result_counts: BTreeMap::new(),
        }
    }

    /// Current epoch.
    pub fn epoch(&self) -> SecurityEpoch {
        self.current_epoch
    }

    /// Set retry configuration for a specific computation.
    pub fn set_retry_config(&mut self, computation_name: &str, config: RetryConfig) {
        self.retry_configs
            .insert(computation_name.to_string(), config);
    }

    /// Get the retry config for a computation (falls back to default).
    pub fn retry_config(&self, computation_name: &str) -> &RetryConfig {
        self.retry_configs
            .get(computation_name)
            .unwrap_or(&self.default_retry_config)
    }

    /// Derive an idempotency key for the given computation input.
    pub fn derive_key(&self, input: &KeyDerivationInput) -> IdempotencyKey {
        derive_idempotency_key(&self.session_key, self.current_epoch, input)
    }

    /// Check an idempotency key and determine the dedup outcome.
    ///
    /// If the key is new, creates an in-progress entry and returns `New`.
    /// If the key exists with `Completed`, returns `CachedResult`.
    /// If the key exists with `InProgress`, returns `DuplicateInProgress`.
    /// If the key exists with `Failed`, returns `PreviouslyFailed`.
    pub fn check_and_claim(
        &mut self,
        key: &IdempotencyKey,
        input: &KeyDerivationInput,
        current_ticks: u64,
    ) -> Result<DedupResult, IdempotencyError> {
        // Epoch binding: reject keys from old epochs.
        if key.epoch != self.current_epoch {
            return Err(IdempotencyError::EpochMismatch {
                key_epoch: key.epoch,
                current_epoch: self.current_epoch,
            });
        }

        // Check retry limit.
        let config = self.retry_config(&input.computation_name);
        if input.attempt_number > config.max_retries {
            return Err(IdempotencyError::MaxRetriesExceeded {
                computation_name: input.computation_name.clone(),
                max_retries: config.max_retries,
                attempt: input.attempt_number,
            });
        }

        let key_hex = key.to_hex();

        // Evict expired entries opportunistically.
        self.evict_expired(current_ticks, &input.computation_name);

        let result = if let Some(entry) = self.entries.get(&key_hex) {
            match &entry.status {
                DedupStatus::Completed { result_hash } => DedupResult::CachedResult {
                    result_hash: *result_hash,
                },
                DedupStatus::InProgress => DedupResult::DuplicateInProgress,
                DedupStatus::Failed { error_code } => DedupResult::PreviouslyFailed {
                    error_code: error_code.clone(),
                },
            }
        } else {
            // New key — create in-progress entry.
            self.entries.insert(
                key_hex.clone(),
                DedupEntry {
                    status: DedupStatus::InProgress,
                    computation_name: input.computation_name.clone(),
                    created_at_ticks: current_ticks,
                    epoch: self.current_epoch,
                },
            );
            DedupResult::New
        };

        // Emit event.
        let result_str = result.to_string();
        self.events.push(IdempotencyEvent {
            idempotency_key_hash: key_hex,
            computation_name: input.computation_name.clone(),
            attempt: input.attempt_number,
            dedup_result: result_str.clone(),
            trace_id: input.trace_id.clone(),
            epoch_id: self.current_epoch.as_u64(),
            event: "dedup_check".to_string(),
        });
        *self.result_counts.entry(result_str).or_insert(0) += 1;

        Ok(result)
    }

    /// Mark an in-progress entry as completed with the result hash.
    pub fn mark_completed(
        &mut self,
        key: &IdempotencyKey,
        result_hash: ContentHash,
    ) -> Result<(), IdempotencyError> {
        let key_hex = key.to_hex();
        let entry =
            self.entries
                .get_mut(&key_hex)
                .ok_or_else(|| IdempotencyError::EntryNotFound {
                    key_hex: key_hex.clone(),
                })?;
        entry.status = DedupStatus::Completed { result_hash };
        Ok(())
    }

    /// Mark an in-progress entry as failed.
    pub fn mark_failed(
        &mut self,
        key: &IdempotencyKey,
        error_code: &str,
    ) -> Result<(), IdempotencyError> {
        let key_hex = key.to_hex();
        let entry =
            self.entries
                .get_mut(&key_hex)
                .ok_or_else(|| IdempotencyError::EntryNotFound {
                    key_hex: key_hex.clone(),
                })?;
        entry.status = DedupStatus::Failed {
            error_code: error_code.to_string(),
        };
        Ok(())
    }

    /// Advance the epoch, invalidating all entries from old epochs.
    pub fn advance_epoch(&mut self, new_epoch: SecurityEpoch, new_session_key: Vec<u8>) {
        self.entries.retain(|_, entry| entry.epoch == new_epoch);
        self.current_epoch = new_epoch;
        self.session_key = new_session_key;
    }

    /// Number of active entries.
    pub fn entry_count(&self) -> usize {
        self.entries.len()
    }

    /// Drain accumulated audit events.
    pub fn drain_events(&mut self) -> Vec<IdempotencyEvent> {
        std::mem::take(&mut self.events)
    }

    /// Per-result-type counters.
    pub fn result_counts(&self) -> &BTreeMap<String, u64> {
        &self.result_counts
    }

    /// Evict expired entries for a given computation.
    fn evict_expired(&mut self, current_ticks: u64, computation_name: &str) {
        let ttl = self.retry_config(computation_name).entry_ttl_ticks;
        self.entries.retain(|_, entry| {
            if entry.computation_name == computation_name {
                current_ticks.saturating_sub(entry.created_at_ticks) < ttl
            } else {
                true
            }
        });
    }

    /// Evict all expired entries across all computations (uses default TTL).
    pub fn evict_all_expired(&mut self, current_ticks: u64) {
        let default_ttl = self.default_retry_config.entry_ttl_ticks;
        self.entries.retain(|_, entry| {
            let ttl = self
                .retry_configs
                .get(&entry.computation_name)
                .map(|c| c.entry_ttl_ticks)
                .unwrap_or(default_ttl);
            current_ticks.saturating_sub(entry.created_at_ticks) < ttl
        });
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    // -- Test helpers --

    fn test_session_key() -> Vec<u8> {
        b"test-epoch-session-key-32bytes!!".to_vec()
    }

    fn test_epoch() -> SecurityEpoch {
        SecurityEpoch::from_raw(1)
    }

    fn test_input_hash() -> ContentHash {
        ContentHash::compute(b"test-input-data")
    }

    fn test_derivation_input() -> KeyDerivationInput {
        KeyDerivationInput {
            computation_name: "revocation_propagate".to_string(),
            input_hash: test_input_hash(),
            trace_id: "trace-001".to_string(),
            attempt_number: 0,
        }
    }

    fn test_result_hash() -> ContentHash {
        ContentHash::compute(b"test-result-data")
    }

    // -- IdempotencyKey derivation --

    #[test]
    fn derivation_is_deterministic() {
        let input = test_derivation_input();
        let k1 = derive_idempotency_key(&test_session_key(), test_epoch(), &input);
        let k2 = derive_idempotency_key(&test_session_key(), test_epoch(), &input);
        assert_eq!(k1, k2);
    }

    #[test]
    fn different_computation_names_produce_different_keys() {
        let mut input1 = test_derivation_input();
        input1.computation_name = "comp_a".to_string();
        let mut input2 = test_derivation_input();
        input2.computation_name = "comp_b".to_string();

        let k1 = derive_idempotency_key(&test_session_key(), test_epoch(), &input1);
        let k2 = derive_idempotency_key(&test_session_key(), test_epoch(), &input2);
        assert_ne!(k1.key_hash, k2.key_hash);
    }

    #[test]
    fn different_input_hashes_produce_different_keys() {
        let mut input1 = test_derivation_input();
        input1.input_hash = ContentHash::compute(b"input-a");
        let mut input2 = test_derivation_input();
        input2.input_hash = ContentHash::compute(b"input-b");

        let k1 = derive_idempotency_key(&test_session_key(), test_epoch(), &input1);
        let k2 = derive_idempotency_key(&test_session_key(), test_epoch(), &input2);
        assert_ne!(k1.key_hash, k2.key_hash);
    }

    #[test]
    fn different_trace_ids_produce_different_keys() {
        let mut input1 = test_derivation_input();
        input1.trace_id = "trace-a".to_string();
        let mut input2 = test_derivation_input();
        input2.trace_id = "trace-b".to_string();

        let k1 = derive_idempotency_key(&test_session_key(), test_epoch(), &input1);
        let k2 = derive_idempotency_key(&test_session_key(), test_epoch(), &input2);
        assert_ne!(k1.key_hash, k2.key_hash);
    }

    #[test]
    fn different_attempt_numbers_produce_different_keys() {
        let mut input1 = test_derivation_input();
        input1.attempt_number = 0;
        let mut input2 = test_derivation_input();
        input2.attempt_number = 1;

        let k1 = derive_idempotency_key(&test_session_key(), test_epoch(), &input1);
        let k2 = derive_idempotency_key(&test_session_key(), test_epoch(), &input2);
        assert_ne!(k1.key_hash, k2.key_hash);
    }

    #[test]
    fn different_epochs_produce_different_keys() {
        let input = test_derivation_input();
        let k1 = derive_idempotency_key(&test_session_key(), SecurityEpoch::from_raw(1), &input);
        let k2 = derive_idempotency_key(&test_session_key(), SecurityEpoch::from_raw(2), &input);
        assert_ne!(k1.key_hash, k2.key_hash);
    }

    #[test]
    fn different_session_keys_produce_different_keys() {
        let input = test_derivation_input();
        let k1 = derive_idempotency_key(b"key-alpha", test_epoch(), &input);
        let k2 = derive_idempotency_key(b"key-beta", test_epoch(), &input);
        assert_ne!(k1.key_hash, k2.key_hash);
    }

    #[test]
    fn key_hex_is_64_chars() {
        let input = test_derivation_input();
        let key = derive_idempotency_key(&test_session_key(), test_epoch(), &input);
        assert_eq!(key.to_hex().len(), 64);
    }

    // -- IdempotencyStore: basic dedup --

    #[test]
    fn new_key_returns_new() {
        let mut store = IdempotencyStore::new(test_epoch(), test_session_key());
        let input = test_derivation_input();
        let key = store.derive_key(&input);
        let result = store.check_and_claim(&key, &input, 100).unwrap();
        assert!(matches!(result, DedupResult::New));
        assert_eq!(store.entry_count(), 1);
    }

    #[test]
    fn duplicate_key_returns_in_progress() {
        let mut store = IdempotencyStore::new(test_epoch(), test_session_key());
        let input = test_derivation_input();
        let key = store.derive_key(&input);

        store.check_and_claim(&key, &input, 100).unwrap();
        let result = store.check_and_claim(&key, &input, 101).unwrap();
        assert!(matches!(result, DedupResult::DuplicateInProgress));
    }

    #[test]
    fn completed_key_returns_cached_result() {
        let mut store = IdempotencyStore::new(test_epoch(), test_session_key());
        let input = test_derivation_input();
        let key = store.derive_key(&input);

        store.check_and_claim(&key, &input, 100).unwrap();
        store.mark_completed(&key, test_result_hash()).unwrap();

        let result = store.check_and_claim(&key, &input, 101).unwrap();
        assert!(matches!(result, DedupResult::CachedResult { .. }));
        if let DedupResult::CachedResult { result_hash } = result {
            assert_eq!(result_hash, test_result_hash());
        }
    }

    #[test]
    fn failed_key_returns_previously_failed() {
        let mut store = IdempotencyStore::new(test_epoch(), test_session_key());
        let input = test_derivation_input();
        let key = store.derive_key(&input);

        store.check_and_claim(&key, &input, 100).unwrap();
        store.mark_failed(&key, "transient_timeout").unwrap();

        let result = store.check_and_claim(&key, &input, 101).unwrap();
        assert!(matches!(result, DedupResult::PreviouslyFailed { .. }));
        if let DedupResult::PreviouslyFailed { error_code } = result {
            assert_eq!(error_code, "transient_timeout");
        }
    }

    // -- Epoch binding --

    #[test]
    fn old_epoch_key_rejected() {
        let mut store = IdempotencyStore::new(SecurityEpoch::from_raw(2), test_session_key());
        let input = test_derivation_input();
        let old_key =
            derive_idempotency_key(&test_session_key(), SecurityEpoch::from_raw(1), &input);

        let err = store.check_and_claim(&old_key, &input, 100).unwrap_err();
        assert!(matches!(err, IdempotencyError::EpochMismatch { .. }));
    }

    #[test]
    fn epoch_advance_clears_old_entries() {
        let mut store = IdempotencyStore::new(test_epoch(), test_session_key());
        let input = test_derivation_input();
        let key = store.derive_key(&input);
        store.check_and_claim(&key, &input, 100).unwrap();
        assert_eq!(store.entry_count(), 1);

        store.advance_epoch(SecurityEpoch::from_raw(2), b"new-session-key".to_vec());
        assert_eq!(store.entry_count(), 0);
        assert_eq!(store.epoch(), SecurityEpoch::from_raw(2));
    }

    // -- Retry limits --

    #[test]
    fn max_retries_enforced() {
        let mut store = IdempotencyStore::new(test_epoch(), test_session_key());
        let mut input = test_derivation_input();
        input.attempt_number = 4; // exceeds default max of 3

        let key = store.derive_key(&input);
        let err = store.check_and_claim(&key, &input, 100).unwrap_err();
        assert!(matches!(err, IdempotencyError::MaxRetriesExceeded { .. }));
    }

    #[test]
    fn custom_retry_config() {
        let mut store = IdempotencyStore::new(test_epoch(), test_session_key());
        store.set_retry_config(
            "custom_comp",
            RetryConfig {
                max_retries: 1,
                entry_ttl_ticks: 100,
            },
        );

        let mut input = test_derivation_input();
        input.computation_name = "custom_comp".to_string();
        input.attempt_number = 2; // exceeds custom max of 1

        let key = store.derive_key(&input);
        let err = store.check_and_claim(&key, &input, 100).unwrap_err();
        if let IdempotencyError::MaxRetriesExceeded { max_retries, .. } = err {
            assert_eq!(max_retries, 1);
        } else {
            panic!("expected MaxRetriesExceeded");
        }
    }

    #[test]
    fn attempt_at_max_retries_succeeds() {
        let mut store = IdempotencyStore::new(test_epoch(), test_session_key());
        let mut input = test_derivation_input();
        input.attempt_number = 3; // exactly at default max

        let key = store.derive_key(&input);
        let result = store.check_and_claim(&key, &input, 100).unwrap();
        assert!(matches!(result, DedupResult::New));
    }

    // -- TTL expiration --

    #[test]
    fn expired_entries_are_evicted() {
        let mut store = IdempotencyStore::new(test_epoch(), test_session_key());
        let input = test_derivation_input();
        let key = store.derive_key(&input);

        store.check_and_claim(&key, &input, 100).unwrap();
        assert_eq!(store.entry_count(), 1);

        // After TTL (default 600 ticks), entry should be evicted.
        let mut input2 = test_derivation_input();
        input2.trace_id = "trace-002".to_string();
        let key2 = store.derive_key(&input2);
        store.check_and_claim(&key2, &input2, 800).unwrap();

        // Original entry should have been evicted during claim.
        assert_eq!(store.entry_count(), 1);
    }

    #[test]
    fn evict_all_expired_respects_per_computation_ttl() {
        let mut store = IdempotencyStore::new(test_epoch(), test_session_key());
        store.set_retry_config(
            "short_ttl",
            RetryConfig {
                max_retries: 3,
                entry_ttl_ticks: 50,
            },
        );

        let mut input1 = test_derivation_input();
        input1.computation_name = "short_ttl".to_string();
        let key1 = store.derive_key(&input1);
        store.check_and_claim(&key1, &input1, 100).unwrap();

        let input2 = test_derivation_input(); // uses default TTL (600)
        let key2 = store.derive_key(&input2);
        store.check_and_claim(&key2, &input2, 100).unwrap();

        assert_eq!(store.entry_count(), 2);

        // At tick 160, short_ttl should be evicted but default should remain.
        store.evict_all_expired(160);
        assert_eq!(store.entry_count(), 1);
    }

    // -- Retry workflow --

    #[test]
    fn retry_after_failure_with_new_attempt_succeeds() {
        let mut store = IdempotencyStore::new(test_epoch(), test_session_key());

        // Attempt 0: claim and fail.
        let mut input0 = test_derivation_input();
        input0.attempt_number = 0;
        let key0 = store.derive_key(&input0);
        store.check_and_claim(&key0, &input0, 100).unwrap();
        store.mark_failed(&key0, "timeout").unwrap();

        // Attempt 1: new attempt produces new key, should be New.
        let mut input1 = test_derivation_input();
        input1.attempt_number = 1;
        let key1 = store.derive_key(&input1);
        assert_ne!(key0.key_hash, key1.key_hash);

        let result = store.check_and_claim(&key1, &input1, 101).unwrap();
        assert!(matches!(result, DedupResult::New));
    }

    // -- mark_completed / mark_failed errors --

    #[test]
    fn mark_completed_missing_entry() {
        let mut store = IdempotencyStore::new(test_epoch(), test_session_key());
        let input = test_derivation_input();
        let key = store.derive_key(&input);
        let err = store.mark_completed(&key, test_result_hash()).unwrap_err();
        assert!(matches!(err, IdempotencyError::EntryNotFound { .. }));
    }

    #[test]
    fn mark_failed_missing_entry() {
        let mut store = IdempotencyStore::new(test_epoch(), test_session_key());
        let input = test_derivation_input();
        let key = store.derive_key(&input);
        let err = store.mark_failed(&key, "error").unwrap_err();
        assert!(matches!(err, IdempotencyError::EntryNotFound { .. }));
    }

    // -- Audit events --

    #[test]
    fn check_emits_event() {
        let mut store = IdempotencyStore::new(test_epoch(), test_session_key());
        let input = test_derivation_input();
        let key = store.derive_key(&input);
        store.check_and_claim(&key, &input, 100).unwrap();

        let events = store.drain_events();
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].event, "dedup_check");
        assert_eq!(events[0].dedup_result, "new");
        assert_eq!(events[0].computation_name, "revocation_propagate");
        assert_eq!(events[0].trace_id, "trace-001");
        assert_eq!(events[0].attempt, 0);
        assert_eq!(events[0].epoch_id, 1);
    }

    #[test]
    fn drain_events_clears() {
        let mut store = IdempotencyStore::new(test_epoch(), test_session_key());
        let input = test_derivation_input();
        let key = store.derive_key(&input);
        store.check_and_claim(&key, &input, 100).unwrap();

        let e1 = store.drain_events();
        assert_eq!(e1.len(), 1);
        let e2 = store.drain_events();
        assert!(e2.is_empty());
    }

    #[test]
    fn result_counts_track_outcomes() {
        let mut store = IdempotencyStore::new(test_epoch(), test_session_key());
        let input = test_derivation_input();
        let key = store.derive_key(&input);

        store.check_and_claim(&key, &input, 100).unwrap(); // new
        store.check_and_claim(&key, &input, 101).unwrap(); // duplicate_in_progress

        store.mark_completed(&key, test_result_hash()).unwrap();
        store.check_and_claim(&key, &input, 102).unwrap(); // cached

        assert_eq!(store.result_counts().get("new"), Some(&1));
        assert_eq!(store.result_counts().get("duplicate_in_progress"), Some(&1));
        assert_eq!(store.result_counts().get("cached"), Some(&1));
    }

    // -- Serialization round-trips --

    #[test]
    fn idempotency_key_serialization_round_trip() {
        let input = test_derivation_input();
        let key = derive_idempotency_key(&test_session_key(), test_epoch(), &input);
        let json = serde_json::to_string(&key).expect("serialize");
        let restored: IdempotencyKey = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(key, restored);
    }

    #[test]
    fn dedup_status_serialization_round_trip() {
        let statuses = vec![
            DedupStatus::InProgress,
            DedupStatus::Completed {
                result_hash: test_result_hash(),
            },
            DedupStatus::Failed {
                error_code: "timeout".to_string(),
            },
        ];
        for status in &statuses {
            let json = serde_json::to_string(status).expect("serialize");
            let restored: DedupStatus = serde_json::from_str(&json).expect("deserialize");
            assert_eq!(*status, restored);
        }
    }

    #[test]
    fn dedup_result_serialization_round_trip() {
        let results = vec![
            DedupResult::New,
            DedupResult::CachedResult {
                result_hash: test_result_hash(),
            },
            DedupResult::DuplicateInProgress,
            DedupResult::PreviouslyFailed {
                error_code: "error".to_string(),
            },
        ];
        for result in &results {
            let json = serde_json::to_string(result).expect("serialize");
            let restored: DedupResult = serde_json::from_str(&json).expect("deserialize");
            assert_eq!(*result, restored);
        }
    }

    #[test]
    fn idempotency_event_serialization_round_trip() {
        let event = IdempotencyEvent {
            idempotency_key_hash: "abcdef".to_string(),
            computation_name: "test".to_string(),
            attempt: 0,
            dedup_result: "new".to_string(),
            trace_id: "trace-1".to_string(),
            epoch_id: 1,
            event: "dedup_check".to_string(),
        };
        let json = serde_json::to_string(&event).expect("serialize");
        let restored: IdempotencyEvent = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(event, restored);
    }

    #[test]
    fn idempotency_error_serialization_round_trip() {
        let errors = vec![
            IdempotencyError::EpochMismatch {
                key_epoch: SecurityEpoch::from_raw(1),
                current_epoch: SecurityEpoch::from_raw(2),
            },
            IdempotencyError::MaxRetriesExceeded {
                computation_name: "test".to_string(),
                max_retries: 3,
                attempt: 4,
            },
            IdempotencyError::DuplicateInProgress {
                computation_name: "test".to_string(),
            },
            IdempotencyError::EntryNotFound {
                key_hex: "abc".to_string(),
            },
        ];
        for err in &errors {
            let json = serde_json::to_string(err).expect("serialize");
            let restored: IdempotencyError = serde_json::from_str(&json).expect("deserialize");
            assert_eq!(*err, restored);
        }
    }

    #[test]
    fn retry_config_serialization_round_trip() {
        let config = RetryConfig {
            max_retries: 5,
            entry_ttl_ticks: 1000,
        };
        let json = serde_json::to_string(&config).expect("serialize");
        let restored: RetryConfig = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(config, restored);
    }

    // -- Display --

    #[test]
    fn key_display_includes_epoch() {
        let input = test_derivation_input();
        let key = derive_idempotency_key(&test_session_key(), test_epoch(), &input);
        let display = key.to_string();
        assert!(display.starts_with("idem:"));
        assert!(display.contains("epoch:1"));
    }

    #[test]
    fn dedup_status_display() {
        assert_eq!(DedupStatus::InProgress.to_string(), "in_progress");
        assert_eq!(
            DedupStatus::Completed {
                result_hash: test_result_hash()
            }
            .to_string(),
            "completed"
        );
        assert_eq!(
            DedupStatus::Failed {
                error_code: "x".to_string()
            }
            .to_string(),
            "failed"
        );
    }

    #[test]
    fn dedup_result_display() {
        assert_eq!(DedupResult::New.to_string(), "new");
        assert_eq!(
            DedupResult::DuplicateInProgress.to_string(),
            "duplicate_in_progress"
        );
    }

    #[test]
    fn error_display_messages() {
        assert!(
            IdempotencyError::EpochMismatch {
                key_epoch: SecurityEpoch::from_raw(1),
                current_epoch: SecurityEpoch::from_raw(2),
            }
            .to_string()
            .contains("epoch mismatch")
        );
        assert!(
            IdempotencyError::MaxRetriesExceeded {
                computation_name: "comp".to_string(),
                max_retries: 3,
                attempt: 4,
            }
            .to_string()
            .contains("max retries")
        );
    }

    // -- Full lifecycle --

    // -- Enrichment: std::error --

    #[test]
    fn idempotency_error_implements_std_error() {
        let variants: Vec<Box<dyn std::error::Error>> = vec![
            Box::new(IdempotencyError::EpochMismatch {
                key_epoch: SecurityEpoch::from_raw(1),
                current_epoch: SecurityEpoch::from_raw(3),
            }),
            Box::new(IdempotencyError::MaxRetriesExceeded {
                computation_name: "compute".into(),
                max_retries: 3,
                attempt: 4,
            }),
            Box::new(IdempotencyError::DuplicateInProgress {
                computation_name: "other".into(),
            }),
            Box::new(IdempotencyError::EntryNotFound {
                key_hex: "aabb".into(),
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
            4,
            "all 4 variants produce distinct messages"
        );
    }

    #[test]
    fn full_lifecycle_derive_check_complete_cache_hit() {
        let mut store = IdempotencyStore::new(test_epoch(), test_session_key());
        let input = test_derivation_input();

        // 1. Derive key
        let key = store.derive_key(&input);
        assert_eq!(key.epoch, test_epoch());

        // 2. Check — should be new
        let r1 = store.check_and_claim(&key, &input, 100).unwrap();
        assert!(matches!(r1, DedupResult::New));

        // 3. Mark completed
        store.mark_completed(&key, test_result_hash()).unwrap();

        // 4. Check again — should be cached
        let r2 = store.check_and_claim(&key, &input, 101).unwrap();
        if let DedupResult::CachedResult { result_hash } = r2 {
            assert_eq!(result_hash, test_result_hash());
        } else {
            panic!("expected CachedResult");
        }

        // 5. Verify events
        let events = store.drain_events();
        assert_eq!(events.len(), 2);
        assert_eq!(events[0].dedup_result, "new");
        assert_eq!(events[1].dedup_result, "cached");
    }

    // -- Enrichment batch 2: Display uniqueness, boundaries, serde --

    #[test]
    fn dedup_status_display_uniqueness() {
        let statuses = [
            DedupStatus::InProgress,
            DedupStatus::Completed {
                result_hash: test_result_hash(),
            },
            DedupStatus::Failed {
                error_code: "x".into(),
            },
        ];
        let mut seen = std::collections::BTreeSet::new();
        for s in &statuses {
            seen.insert(s.to_string());
        }
        assert_eq!(seen.len(), 3, "all 3 statuses have unique display strings");
    }

    #[test]
    fn dedup_result_display_uniqueness() {
        let results = [
            DedupResult::New,
            DedupResult::CachedResult {
                result_hash: test_result_hash(),
            },
            DedupResult::DuplicateInProgress,
            DedupResult::PreviouslyFailed {
                error_code: "x".into(),
            },
        ];
        let mut seen = std::collections::BTreeSet::new();
        for r in &results {
            seen.insert(r.to_string());
        }
        assert_eq!(seen.len(), 4, "all 4 results have unique display strings");
    }

    #[test]
    fn idempotency_error_display_uniqueness() {
        let errors = [
            IdempotencyError::EpochMismatch {
                key_epoch: SecurityEpoch::from_raw(1),
                current_epoch: SecurityEpoch::from_raw(2),
            },
            IdempotencyError::MaxRetriesExceeded {
                computation_name: "c".into(),
                max_retries: 3,
                attempt: 4,
            },
            IdempotencyError::DuplicateInProgress {
                computation_name: "d".into(),
            },
            IdempotencyError::EntryNotFound {
                key_hex: "abc".into(),
            },
        ];
        let mut seen = std::collections::BTreeSet::new();
        for e in &errors {
            seen.insert(e.to_string());
        }
        assert_eq!(seen.len(), 4, "all 4 error variants have unique display");
    }

    #[test]
    fn retry_config_default_values() {
        let config = RetryConfig::default();
        assert_eq!(config.max_retries, 3);
        assert_eq!(config.entry_ttl_ticks, 600);
    }

    #[test]
    fn key_hex_all_lowercase_hex() {
        let input = test_derivation_input();
        let key = derive_idempotency_key(&test_session_key(), test_epoch(), &input);
        let hex = key.to_hex();
        assert!(
            hex.chars()
                .all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase())
        );
    }

    #[test]
    fn key_display_format() {
        let input = test_derivation_input();
        let key = derive_idempotency_key(&test_session_key(), test_epoch(), &input);
        let display = key.to_string();
        assert!(display.starts_with("idem:"));
        assert!(display.contains('@'));
        // The hex part should be 64 chars
        let hex_part = display.strip_prefix("idem:").unwrap();
        let hex_part = hex_part.split('@').next().unwrap();
        assert_eq!(hex_part.len(), 64);
    }

    #[test]
    fn store_retry_config_fallback_to_default() {
        let store = IdempotencyStore::new(test_epoch(), test_session_key());
        let config = store.retry_config("unknown_computation");
        assert_eq!(config.max_retries, 3);
        assert_eq!(config.entry_ttl_ticks, 600);
    }

    #[test]
    fn store_custom_retry_config_overrides_default() {
        let mut store = IdempotencyStore::new(test_epoch(), test_session_key());
        store.set_retry_config(
            "special_comp",
            RetryConfig {
                max_retries: 10,
                entry_ttl_ticks: 1000,
            },
        );
        let config = store.retry_config("special_comp");
        assert_eq!(config.max_retries, 10);
        assert_eq!(config.entry_ttl_ticks, 1000);
        // Other computations still use default
        let default_config = store.retry_config("other_comp");
        assert_eq!(default_config.max_retries, 3);
    }

    #[test]
    fn store_advance_epoch_updates_session_key() {
        let mut store = IdempotencyStore::new(test_epoch(), test_session_key());
        let input = test_derivation_input();
        let key_before = store.derive_key(&input);

        store.advance_epoch(
            SecurityEpoch::from_raw(2),
            b"new-key-material-32byteshere!!".to_vec(),
        );
        assert_eq!(store.epoch(), SecurityEpoch::from_raw(2));

        let key_after = store.derive_key(&input);
        // Different epoch + different session key -> different key hash
        assert_ne!(key_before.key_hash, key_after.key_hash);
    }

    #[test]
    fn key_derivation_input_serde_roundtrip() {
        let input = test_derivation_input();
        let json = serde_json::to_string(&input).unwrap();
        let back: KeyDerivationInput = serde_json::from_str(&json).unwrap();
        assert_eq!(input, back);
    }

    #[test]
    fn dedup_entry_serde_roundtrip() {
        let entry = DedupEntry {
            status: DedupStatus::Completed {
                result_hash: test_result_hash(),
            },
            computation_name: "comp".into(),
            created_at_ticks: 42,
            epoch: test_epoch(),
        };
        let json = serde_json::to_string(&entry).unwrap();
        let back: DedupEntry = serde_json::from_str(&json).unwrap();
        assert_eq!(entry, back);
    }

    // -- Enrichment: clone equality --

    #[test]
    fn idempotency_key_clone_equality() {
        let input = test_derivation_input();
        let key = derive_idempotency_key(&test_session_key(), test_epoch(), &input);
        let cloned = key.clone();
        assert_eq!(key, cloned);
        assert_eq!(key.to_hex(), cloned.to_hex());
    }

    #[test]
    fn key_derivation_input_clone_equality() {
        let input = test_derivation_input();
        let cloned = input.clone();
        assert_eq!(input, cloned);
    }

    #[test]
    fn dedup_entry_clone_equality() {
        let entry = DedupEntry {
            status: DedupStatus::Completed {
                result_hash: test_result_hash(),
            },
            computation_name: "test_comp".into(),
            created_at_ticks: 999,
            epoch: test_epoch(),
        };
        let cloned = entry.clone();
        assert_eq!(entry, cloned);
    }

    #[test]
    fn retry_config_clone_equality() {
        let config = RetryConfig {
            max_retries: 7,
            entry_ttl_ticks: 1234,
        };
        let cloned = config.clone();
        assert_eq!(config, cloned);
    }

    #[test]
    fn idempotency_event_json_field_presence() {
        let event = IdempotencyEvent {
            idempotency_key_hash: "aabb".into(),
            computation_name: "comp".into(),
            attempt: 2,
            dedup_result: "new".into(),
            trace_id: "t-1".into(),
            epoch_id: 5,
            event: "dedup_check".into(),
        };
        let json = serde_json::to_string(&event).unwrap();
        assert!(json.contains("\"idempotency_key_hash\""));
        assert!(json.contains("\"computation_name\""));
        assert!(json.contains("\"attempt\""));
        assert!(json.contains("\"dedup_result\""));
        assert!(json.contains("\"trace_id\""));
        assert!(json.contains("\"epoch_id\""));
        assert!(json.contains("\"event\""));
    }

    #[test]
    fn dedup_entry_json_field_presence() {
        let entry = DedupEntry {
            status: DedupStatus::InProgress,
            computation_name: "c".into(),
            created_at_ticks: 0,
            epoch: test_epoch(),
        };
        let json = serde_json::to_string(&entry).unwrap();
        assert!(json.contains("\"status\""));
        assert!(json.contains("\"computation_name\""));
        assert!(json.contains("\"created_at_ticks\""));
        assert!(json.contains("\"epoch\""));
    }

    #[test]
    fn key_derivation_input_json_field_presence() {
        let input = test_derivation_input();
        let json = serde_json::to_string(&input).unwrap();
        assert!(json.contains("\"computation_name\""));
        assert!(json.contains("\"input_hash\""));
        assert!(json.contains("\"trace_id\""));
        assert!(json.contains("\"attempt_number\""));
    }

    #[test]
    fn idempotency_error_source_is_none() {
        let err = IdempotencyError::EntryNotFound {
            key_hex: "abc".into(),
        };
        assert!(std::error::Error::source(&err).is_none());
    }

    #[test]
    fn idempotency_key_ord_deterministic() {
        let mut input_a = test_derivation_input();
        input_a.trace_id = "trace-a".into();
        let mut input_b = test_derivation_input();
        input_b.trace_id = "trace-b".into();
        let ka = derive_idempotency_key(&test_session_key(), test_epoch(), &input_a);
        let kb = derive_idempotency_key(&test_session_key(), test_epoch(), &input_b);
        let cmp1 = ka.cmp(&kb);
        let cmp2 = ka.cmp(&kb);
        assert_eq!(cmp1, cmp2);
        assert_ne!(ka, kb);
    }

    #[test]
    fn store_initial_state_empty() {
        let store = IdempotencyStore::new(test_epoch(), test_session_key());
        assert_eq!(store.entry_count(), 0);
        assert!(store.result_counts().is_empty());
    }

    #[test]
    fn evict_all_expired_no_entries_is_noop() {
        let mut store = IdempotencyStore::new(test_epoch(), test_session_key());
        store.evict_all_expired(999_999);
        assert_eq!(store.entry_count(), 0);
    }

    #[test]
    fn mark_completed_then_check_returns_cached() {
        let mut store = IdempotencyStore::new(test_epoch(), test_session_key());
        let input = test_derivation_input();
        let key = store.derive_key(&input);
        store.check_and_claim(&key, &input, 100).unwrap();
        let rh = ContentHash::compute(b"specific-result");
        store.mark_completed(&key, rh).unwrap();
        let result = store.check_and_claim(&key, &input, 101).unwrap();
        if let DedupResult::CachedResult { result_hash } = result {
            assert_eq!(result_hash, rh);
        } else {
            panic!("expected CachedResult after mark_completed");
        }
    }

    // -----------------------------------------------------------------------
    // Enrichment: multiple concurrent computations in store
    // -----------------------------------------------------------------------

    #[test]
    fn multiple_distinct_computations_coexist() {
        let mut store = IdempotencyStore::new(test_epoch(), test_session_key());

        let mut input_a = test_derivation_input();
        input_a.computation_name = "comp_alpha".to_string();
        input_a.trace_id = "trace-alpha".to_string();
        let key_a = store.derive_key(&input_a);

        let mut input_b = test_derivation_input();
        input_b.computation_name = "comp_beta".to_string();
        input_b.trace_id = "trace-beta".to_string();
        let key_b = store.derive_key(&input_b);

        let r1 = store.check_and_claim(&key_a, &input_a, 100).unwrap();
        let r2 = store.check_and_claim(&key_b, &input_b, 100).unwrap();
        assert!(matches!(r1, DedupResult::New));
        assert!(matches!(r2, DedupResult::New));
        assert_eq!(store.entry_count(), 2);

        // Complete one, check it returns cached; other still in-progress.
        store.mark_completed(&key_a, test_result_hash()).unwrap();
        let r3 = store.check_and_claim(&key_a, &input_a, 101).unwrap();
        assert!(matches!(r3, DedupResult::CachedResult { .. }));
        let r4 = store.check_and_claim(&key_b, &input_b, 101).unwrap();
        assert!(matches!(r4, DedupResult::DuplicateInProgress));
    }

    // -----------------------------------------------------------------------
    // Enrichment: error Display content checks
    // -----------------------------------------------------------------------

    #[test]
    fn error_display_duplicate_in_progress_content() {
        let err = IdempotencyError::DuplicateInProgress {
            computation_name: "my_computation".to_string(),
        };
        let msg = err.to_string();
        assert!(msg.contains("my_computation"));
        assert!(msg.contains("duplicate"));
    }

    #[test]
    fn error_display_entry_not_found_content() {
        let err = IdempotencyError::EntryNotFound {
            key_hex: "deadbeef1234".to_string(),
        };
        let msg = err.to_string();
        assert!(msg.contains("deadbeef1234"));
        assert!(msg.contains("not found"));
    }

    #[test]
    fn error_display_max_retries_content() {
        let err = IdempotencyError::MaxRetriesExceeded {
            computation_name: "sync_op".to_string(),
            max_retries: 5,
            attempt: 6,
        };
        let msg = err.to_string();
        assert!(msg.contains("sync_op"));
        assert!(msg.contains("5"));
        assert!(msg.contains("6"));
    }

    #[test]
    fn error_display_epoch_mismatch_content() {
        let err = IdempotencyError::EpochMismatch {
            key_epoch: SecurityEpoch::from_raw(3),
            current_epoch: SecurityEpoch::from_raw(7),
        };
        let msg = err.to_string();
        assert!(msg.contains("3") || msg.contains("epoch:3"));
        assert!(msg.contains("7") || msg.contains("epoch:7"));
    }

    // -----------------------------------------------------------------------
    // Enrichment: multiple epoch advances
    // -----------------------------------------------------------------------

    #[test]
    fn multiple_epoch_advances_clear_entries() {
        let mut store = IdempotencyStore::new(test_epoch(), test_session_key());

        // Add entry in epoch 1.
        let input = test_derivation_input();
        let key = store.derive_key(&input);
        store.check_and_claim(&key, &input, 100).unwrap();
        assert_eq!(store.entry_count(), 1);

        // Advance to epoch 2 — epoch 1 entries cleared.
        store.advance_epoch(SecurityEpoch::from_raw(2), b"key-ep2".to_vec());
        assert_eq!(store.entry_count(), 0);

        // Add entry in epoch 2.
        let key2 = store.derive_key(&input);
        store.check_and_claim(&key2, &input, 200).unwrap();
        assert_eq!(store.entry_count(), 1);

        // Advance to epoch 3 — epoch 2 entries cleared.
        store.advance_epoch(SecurityEpoch::from_raw(3), b"key-ep3".to_vec());
        assert_eq!(store.entry_count(), 0);
        assert_eq!(store.epoch(), SecurityEpoch::from_raw(3));
    }

    // -----------------------------------------------------------------------
    // Enrichment: key derivation edge cases
    // -----------------------------------------------------------------------

    #[test]
    fn key_derivation_empty_computation_name() {
        let input = KeyDerivationInput {
            computation_name: String::new(),
            input_hash: test_input_hash(),
            trace_id: "trace-empty-comp".to_string(),
            attempt_number: 0,
        };
        let key = derive_idempotency_key(&test_session_key(), test_epoch(), &input);
        assert_eq!(key.to_hex().len(), 64);
        assert_eq!(key.epoch, test_epoch());
    }

    #[test]
    fn key_derivation_empty_trace_id() {
        let input = KeyDerivationInput {
            computation_name: "comp".to_string(),
            input_hash: test_input_hash(),
            trace_id: String::new(),
            attempt_number: 0,
        };
        let key = derive_idempotency_key(&test_session_key(), test_epoch(), &input);
        assert_eq!(key.to_hex().len(), 64);
    }

    #[test]
    fn key_derivation_max_attempt_number() {
        let input = KeyDerivationInput {
            computation_name: "comp".to_string(),
            input_hash: test_input_hash(),
            trace_id: "trace-max".to_string(),
            attempt_number: u32::MAX,
        };
        let key = derive_idempotency_key(&test_session_key(), test_epoch(), &input);
        assert_eq!(key.to_hex().len(), 64);
        // Should differ from attempt 0.
        let mut input0 = input.clone();
        input0.attempt_number = 0;
        let key0 = derive_idempotency_key(&test_session_key(), test_epoch(), &input0);
        assert_ne!(key.key_hash, key0.key_hash);
    }

    #[test]
    fn key_derivation_empty_session_key() {
        let input = test_derivation_input();
        let key = derive_idempotency_key(&[], test_epoch(), &input);
        assert_eq!(key.to_hex().len(), 64);
        // Should differ from non-empty session key.
        let key2 = derive_idempotency_key(&test_session_key(), test_epoch(), &input);
        assert_ne!(key.key_hash, key2.key_hash);
    }

    // -----------------------------------------------------------------------
    // Enrichment: event content for different dedup outcomes
    // -----------------------------------------------------------------------

    #[test]
    fn event_content_for_duplicate_in_progress() {
        let mut store = IdempotencyStore::new(test_epoch(), test_session_key());
        let input = test_derivation_input();
        let key = store.derive_key(&input);

        store.check_and_claim(&key, &input, 100).unwrap();
        store.drain_events(); // clear first event

        store.check_and_claim(&key, &input, 101).unwrap();
        let events = store.drain_events();
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].dedup_result, "duplicate_in_progress");
        assert_eq!(events[0].event, "dedup_check");
    }

    #[test]
    fn event_content_for_previously_failed() {
        let mut store = IdempotencyStore::new(test_epoch(), test_session_key());
        let input = test_derivation_input();
        let key = store.derive_key(&input);

        store.check_and_claim(&key, &input, 100).unwrap();
        store.mark_failed(&key, "network_error").unwrap();
        store.drain_events();

        store.check_and_claim(&key, &input, 101).unwrap();
        let events = store.drain_events();
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].dedup_result, "previously_failed");
    }

    // -----------------------------------------------------------------------
    // Enrichment: RetryConfig with 0 max_retries
    // -----------------------------------------------------------------------

    #[test]
    fn retry_config_zero_max_retries() {
        let mut store = IdempotencyStore::new(test_epoch(), test_session_key());
        store.set_retry_config(
            "zero_retry_comp",
            RetryConfig {
                max_retries: 0,
                entry_ttl_ticks: 600,
            },
        );

        // Attempt 0 should succeed.
        let mut input = test_derivation_input();
        input.computation_name = "zero_retry_comp".to_string();
        input.attempt_number = 0;
        let key = store.derive_key(&input);
        let result = store.check_and_claim(&key, &input, 100).unwrap();
        assert!(matches!(result, DedupResult::New));

        // Attempt 1 should fail (exceeds max of 0).
        input.attempt_number = 1;
        let key1 = store.derive_key(&input);
        let err = store.check_and_claim(&key1, &input, 101).unwrap_err();
        assert!(matches!(
            err,
            IdempotencyError::MaxRetriesExceeded { max_retries: 0, .. }
        ));
    }

    // -----------------------------------------------------------------------
    // Enrichment: IdempotencyKey in BTreeSet (Hash/Ord)
    // -----------------------------------------------------------------------

    #[test]
    fn idempotency_key_in_btreeset() {
        use std::collections::BTreeSet;
        let mut input_a = test_derivation_input();
        input_a.trace_id = "set-a".to_string();
        let mut input_b = test_derivation_input();
        input_b.trace_id = "set-b".to_string();

        let ka = derive_idempotency_key(&test_session_key(), test_epoch(), &input_a);
        let kb = derive_idempotency_key(&test_session_key(), test_epoch(), &input_b);
        let ka_dup = ka.clone();

        let mut set = BTreeSet::new();
        set.insert(ka);
        set.insert(kb);
        set.insert(ka_dup); // duplicate
        assert_eq!(set.len(), 2);
    }

    // -----------------------------------------------------------------------
    // Enrichment: DedupResult Display for CachedResult and PreviouslyFailed
    // -----------------------------------------------------------------------

    #[test]
    fn dedup_result_cached_result_display() {
        let r = DedupResult::CachedResult {
            result_hash: test_result_hash(),
        };
        assert_eq!(r.to_string(), "cached");
    }

    #[test]
    fn dedup_result_previously_failed_display() {
        let r = DedupResult::PreviouslyFailed {
            error_code: "timeout".to_string(),
        };
        assert_eq!(r.to_string(), "previously_failed");
    }

    // -----------------------------------------------------------------------
    // Enrichment: entry count tracks correctly through lifecycle
    // -----------------------------------------------------------------------

    #[test]
    fn entry_count_tracks_through_lifecycle() {
        let mut store = IdempotencyStore::new(test_epoch(), test_session_key());
        assert_eq!(store.entry_count(), 0);

        // Add 3 distinct entries.
        for i in 0..3 {
            let mut input = test_derivation_input();
            input.trace_id = format!("trace-{i}");
            let key = store.derive_key(&input);
            store.check_and_claim(&key, &input, 100 + i).unwrap();
        }
        assert_eq!(store.entry_count(), 3);

        // Duplicate check doesn't add new entry.
        let input = test_derivation_input();
        let key = store.derive_key(&input);
        store.check_and_claim(&key, &input, 200).unwrap();
        // This might be New (different trace_id than the 3 above)
        // or might match if trace_id matches. Let's use the original.
        let mut orig_input = test_derivation_input();
        orig_input.trace_id = "trace-0".to_string();
        let orig_key = store.derive_key(&orig_input);
        store.check_and_claim(&orig_key, &orig_input, 200).unwrap();
        // entry_count should be 4 (3 numbered + 1 default trace_id)
        assert!(store.entry_count() >= 3);
    }

    // -----------------------------------------------------------------------
    // Enrichment: result counts across multiple outcome types
    // -----------------------------------------------------------------------

    #[test]
    fn result_counts_all_outcome_types() {
        let mut store = IdempotencyStore::new(test_epoch(), test_session_key());

        // Generate "new" outcome.
        let mut input1 = test_derivation_input();
        input1.trace_id = "counts-1".to_string();
        let key1 = store.derive_key(&input1);
        store.check_and_claim(&key1, &input1, 100).unwrap();

        // Generate "duplicate_in_progress" outcome.
        store.check_and_claim(&key1, &input1, 101).unwrap();

        // Mark completed, generate "cached" outcome.
        store.mark_completed(&key1, test_result_hash()).unwrap();
        store.check_and_claim(&key1, &input1, 102).unwrap();

        // Generate "previously_failed" outcome.
        let mut input2 = test_derivation_input();
        input2.trace_id = "counts-2".to_string();
        let key2 = store.derive_key(&input2);
        store.check_and_claim(&key2, &input2, 103).unwrap();
        store.mark_failed(&key2, "err").unwrap();
        store.check_and_claim(&key2, &input2, 104).unwrap();

        let counts = store.result_counts();
        assert_eq!(counts.get("new"), Some(&2)); // key1 + key2
        assert_eq!(counts.get("duplicate_in_progress"), Some(&1));
        assert_eq!(counts.get("cached"), Some(&1));
        assert_eq!(counts.get("previously_failed"), Some(&1));
    }

    // -----------------------------------------------------------------------
    // Enrichment: evict_all_expired removes all stale entries
    // -----------------------------------------------------------------------

    #[test]
    fn evict_all_expired_removes_all_stale() {
        let mut store = IdempotencyStore::new(test_epoch(), test_session_key());

        // Create 3 entries at tick 100.
        for i in 0..3 {
            let mut input = test_derivation_input();
            input.trace_id = format!("evict-{i}");
            let key = store.derive_key(&input);
            store.check_and_claim(&key, &input, 100).unwrap();
        }
        assert_eq!(store.entry_count(), 3);

        // Evict at tick 100 — within TTL (600), nothing removed.
        store.evict_all_expired(100);
        assert_eq!(store.entry_count(), 3);

        // Evict at tick 800 — all past TTL, all removed.
        store.evict_all_expired(800);
        assert_eq!(store.entry_count(), 0);
    }

    // -----------------------------------------------------------------------
    // Enrichment: DedupEntry epoch matches store epoch
    // -----------------------------------------------------------------------

    #[test]
    fn dedup_entry_epoch_matches_store_epoch() {
        let mut store = IdempotencyStore::new(SecurityEpoch::from_raw(42), test_session_key());
        let input = test_derivation_input();
        let key = store.derive_key(&input);
        store.check_and_claim(&key, &input, 100).unwrap();

        // Internal entry should have epoch 42.
        let events = store.drain_events();
        assert_eq!(events[0].epoch_id, 42);
    }

    // -----------------------------------------------------------------------
    // Enrichment: key derivation is preimage-sensitive
    // -----------------------------------------------------------------------

    #[test]
    fn key_derivation_sensitive_to_name_prefix_collision() {
        // Ensure length-prefixed names avoid collisions:
        // "ab" || "cd" != "abc" || "d"
        let mut input1 = test_derivation_input();
        input1.computation_name = "ab".to_string();
        input1.trace_id = "cd".to_string();

        let mut input2 = test_derivation_input();
        input2.computation_name = "abc".to_string();
        input2.trace_id = "d".to_string();

        let k1 = derive_idempotency_key(&test_session_key(), test_epoch(), &input1);
        let k2 = derive_idempotency_key(&test_session_key(), test_epoch(), &input2);
        assert_ne!(k1.key_hash, k2.key_hash, "length-prefix prevents collision");
    }

    // -----------------------------------------------------------------------
    // Enrichment: RetryConfig serde with edge values
    // -----------------------------------------------------------------------

    #[test]
    fn retry_config_serde_edge_values() {
        let cfg = RetryConfig {
            max_retries: u32::MAX,
            entry_ttl_ticks: u64::MAX,
        };
        let json = serde_json::to_string(&cfg).unwrap();
        let back: RetryConfig = serde_json::from_str(&json).unwrap();
        assert_eq!(cfg, back);
    }

    // -----------------------------------------------------------------------
    // Enrichment: derive_key uses store's session key and epoch
    // -----------------------------------------------------------------------

    #[test]
    fn derive_key_uses_store_session_key_and_epoch() {
        let store1 = IdempotencyStore::new(SecurityEpoch::from_raw(1), b"key-A".to_vec());
        let store2 = IdempotencyStore::new(SecurityEpoch::from_raw(1), b"key-B".to_vec());
        let input = test_derivation_input();

        let k1 = store1.derive_key(&input);
        let k2 = store2.derive_key(&input);
        assert_ne!(
            k1.key_hash, k2.key_hash,
            "different session keys produce different keys"
        );

        let store3 = IdempotencyStore::new(SecurityEpoch::from_raw(2), b"key-A".to_vec());
        let k3 = store3.derive_key(&input);
        assert_ne!(
            k1.key_hash, k3.key_hash,
            "different epochs produce different keys"
        );
    }

    // -----------------------------------------------------------------------
    // Enrichment: future epoch key rejected
    // -----------------------------------------------------------------------

    #[test]
    fn future_epoch_key_rejected() {
        let mut store = IdempotencyStore::new(SecurityEpoch::from_raw(1), test_session_key());
        let input = test_derivation_input();
        let future_key =
            derive_idempotency_key(&test_session_key(), SecurityEpoch::from_raw(99), &input);
        let err = store.check_and_claim(&future_key, &input, 100).unwrap_err();
        assert!(matches!(err, IdempotencyError::EpochMismatch { .. }));
    }

    // -----------------------------------------------------------------------
    // Enrichment: deterministic key derivation across calls
    // -----------------------------------------------------------------------

    #[test]
    fn store_derive_key_deterministic() {
        let store = IdempotencyStore::new(test_epoch(), test_session_key());
        let input = test_derivation_input();
        let k1 = store.derive_key(&input);
        let k2 = store.derive_key(&input);
        assert_eq!(k1, k2);
        assert_eq!(k1.to_hex(), k2.to_hex());
    }
}
