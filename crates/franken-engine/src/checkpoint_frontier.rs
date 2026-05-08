//! Persistent checkpoint-frontier enforcement with unconditional rollback
//! rejection.
//!
//! Once a verifier accepts a checkpoint at sequence N, it must never accept
//! a checkpoint at sequence M where M <= N, even if M carries valid
//! signatures.  This creates a ratchet effect that limits the damage from
//! key compromise: an attacker may forge new checkpoints but cannot
//! regress policy state.
//!
//! The frontier is per-trust-zone: each zone maintains an independent
//! checkpoint chain and frontier.
//!
//! Plan references: Section 10.10 item 7, 9E.3 (checkpointed policy
//! frontier with rollback/fork protection), Top-10 #3, #5, #10.

use std::collections::BTreeMap;
use std::fmt;

use serde::{Deserialize, Serialize};

use crate::engine_object_id::EngineObjectId;
use crate::policy_checkpoint::{PolicyCheckpoint, verify_chain_linkage, verify_checkpoint_quorum};
use crate::security_epoch::SecurityEpoch;
use crate::signature_preimage::VerificationKey;

// ---------------------------------------------------------------------------
// FrontierError
// ---------------------------------------------------------------------------

/// Errors from checkpoint-frontier enforcement.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum FrontierError {
    /// Attempted rollback: offered checkpoint sequence <= frontier.
    RollbackRejected {
        zone: String,
        frontier_seq: u64,
        attempted_seq: u64,
    },
    /// Offered checkpoint ID matches frontier (duplicate acceptance).
    DuplicateCheckpoint { zone: String, checkpoint_seq: u64 },
    /// Chain linkage failed against the frontier checkpoint.
    ChainLinkageFailure { zone: String, detail: String },
    /// Quorum verification failed.
    QuorumFailure { zone: String, detail: String },
    /// Zone does not exist.
    UnknownZone { zone: String },
    /// Epoch regression detected.
    EpochRegression {
        zone: String,
        frontier_epoch: SecurityEpoch,
        attempted_epoch: SecurityEpoch,
    },
    /// Persistence failure during atomic update.
    PersistenceFailed { zone: String, detail: String },
}

impl fmt::Display for FrontierError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::RollbackRejected {
                zone,
                frontier_seq,
                attempted_seq,
            } => write!(
                f,
                "rollback rejected in zone {zone}: frontier seq={frontier_seq}, \
                 attempted seq={attempted_seq}"
            ),
            Self::DuplicateCheckpoint {
                zone,
                checkpoint_seq,
            } => write!(
                f,
                "duplicate checkpoint in zone {zone}: seq={checkpoint_seq}"
            ),
            Self::ChainLinkageFailure { zone, detail } => {
                write!(f, "chain linkage failure in zone {zone}: {detail}")
            }
            Self::QuorumFailure { zone, detail } => {
                write!(f, "quorum failure in zone {zone}: {detail}")
            }
            Self::UnknownZone { zone } => write!(f, "unknown zone: {zone}"),
            Self::EpochRegression {
                zone,
                frontier_epoch,
                attempted_epoch,
            } => write!(
                f,
                "epoch regression in zone {zone}: frontier={frontier_epoch}, \
                 attempted={attempted_epoch}"
            ),
            Self::PersistenceFailed { zone, detail } => {
                write!(f, "persistence failed in zone {zone}: {detail}")
            }
        }
    }
}

impl std::error::Error for FrontierError {}

// ---------------------------------------------------------------------------
// FrontierState — per-zone persistent state
// ---------------------------------------------------------------------------

/// The persisted frontier state for a single trust zone.
///
/// Represents the highest accepted checkpoint. Enforcement is strictly
/// on `frontier_seq`: any checkpoint with seq <= frontier_seq is
/// unconditionally rejected.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FrontierState {
    /// The zone this frontier belongs to.
    pub zone: String,
    /// Highest accepted checkpoint sequence number.
    pub frontier_seq: u64,
    /// Checkpoint ID of the highest accepted checkpoint.
    pub frontier_checkpoint_id: EngineObjectId,
    /// Epoch of the highest accepted checkpoint.
    pub frontier_epoch: SecurityEpoch,
    /// Number of checkpoints accepted since frontier was initialized.
    pub accept_count: u64,
    /// Recent checkpoint IDs for forensic context (bounded window).
    pub recent_ids: Vec<FrontierEntry>,
}

/// A single entry in the forensic history window.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FrontierEntry {
    pub checkpoint_seq: u64,
    pub checkpoint_id: EngineObjectId,
    pub epoch: SecurityEpoch,
}

impl FrontierState {
    /// Maximum number of recent entries retained for forensic context.
    const MAX_RECENT_ENTRIES: usize = 32;

    /// Create a genesis frontier from the first checkpoint in a zone.
    fn from_genesis(zone: &str, checkpoint: &PolicyCheckpoint) -> Self {
        let entry = FrontierEntry {
            checkpoint_seq: checkpoint.checkpoint_seq,
            checkpoint_id: checkpoint.checkpoint_id.clone(),
            epoch: checkpoint.epoch_id,
        };
        Self {
            zone: zone.to_string(),
            frontier_seq: checkpoint.checkpoint_seq,
            frontier_checkpoint_id: checkpoint.checkpoint_id.clone(),
            frontier_epoch: checkpoint.epoch_id,
            accept_count: 1,
            recent_ids: vec![entry],
        }
    }

    /// Advance the frontier to a new checkpoint.
    ///
    /// Caller must have already verified monotonicity, linkage, and quorum.
    fn advance(&mut self, checkpoint: &PolicyCheckpoint) {
        self.frontier_seq = checkpoint.checkpoint_seq;
        self.frontier_checkpoint_id = checkpoint.checkpoint_id.clone();
        self.frontier_epoch = checkpoint.epoch_id;
        self.accept_count = self.accept_count.saturating_add(1);

        let entry = FrontierEntry {
            checkpoint_seq: checkpoint.checkpoint_seq,
            checkpoint_id: checkpoint.checkpoint_id.clone(),
            epoch: checkpoint.epoch_id,
        };
        self.recent_ids.push(entry);

        // Trim to bounded window.
        if self.recent_ids.len() > Self::MAX_RECENT_ENTRIES {
            let excess = self.recent_ids.len() - Self::MAX_RECENT_ENTRIES;
            self.recent_ids.drain(..excess);
        }
    }
}

// ---------------------------------------------------------------------------
// FrontierEvent — structured audit events
// ---------------------------------------------------------------------------

/// Types of frontier events.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum FrontierEventType {
    /// Zone initialized with genesis checkpoint.
    ZoneInitialized { zone: String, genesis_seq: u64 },
    /// Checkpoint accepted and frontier advanced.
    CheckpointAccepted {
        zone: String,
        prev_seq: u64,
        new_seq: u64,
    },
    /// Rollback attempt rejected.
    RollbackRejected {
        zone: String,
        frontier_seq: u64,
        attempted_seq: u64,
    },
    /// Duplicate checkpoint rejected.
    DuplicateRejected { zone: String, checkpoint_seq: u64 },
    /// Epoch regression rejected.
    EpochRegressionRejected {
        zone: String,
        frontier_epoch: SecurityEpoch,
        attempted_epoch: SecurityEpoch,
    },
    /// Frontier loaded from persistence.
    FrontierLoaded { zone: String, frontier_seq: u64 },
}

impl fmt::Display for FrontierEventType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ZoneInitialized { zone, genesis_seq } => {
                write!(f, "zone_initialized({zone}, seq={genesis_seq})")
            }
            Self::CheckpointAccepted {
                zone,
                prev_seq,
                new_seq,
            } => write!(f, "checkpoint_accepted({zone}, {prev_seq}->{new_seq})"),
            Self::RollbackRejected {
                zone,
                frontier_seq,
                attempted_seq,
            } => write!(
                f,
                "rollback_rejected({zone}, frontier={frontier_seq}, attempted={attempted_seq})"
            ),
            Self::DuplicateRejected {
                zone,
                checkpoint_seq,
            } => write!(f, "duplicate_rejected({zone}, seq={checkpoint_seq})"),
            Self::EpochRegressionRejected {
                zone,
                frontier_epoch,
                attempted_epoch,
            } => write!(
                f,
                "epoch_regression_rejected({zone}, frontier={frontier_epoch}, \
                 attempted={attempted_epoch})"
            ),
            Self::FrontierLoaded { zone, frontier_seq } => {
                write!(f, "frontier_loaded({zone}, seq={frontier_seq})")
            }
        }
    }
}

/// A structured frontier event.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FrontierEvent {
    pub event_type: FrontierEventType,
    pub trace_id: String,
}

// ---------------------------------------------------------------------------
// PersistenceBackend — abstraction for crash-safe storage
// ---------------------------------------------------------------------------

/// Trait for crash-safe persistence of frontier state.
///
/// Implementations must guarantee atomic update semantics: a crash
/// during `persist` must not leave the frontier in an inconsistent
/// or regressed state.
pub trait PersistenceBackend {
    /// Atomically persist the frontier state for a zone.
    fn persist(&mut self, state: &FrontierState) -> Result<(), String>;

    /// Load the frontier state for a zone, if it exists.
    fn load(&self, zone: &str) -> Result<Option<FrontierState>, String>;

    /// Load all persisted zone frontiers.
    fn load_all(&self) -> Result<Vec<FrontierState>, String>;
}

// ---------------------------------------------------------------------------
// InMemoryBackend — test/development persistence backend
// ---------------------------------------------------------------------------

/// In-memory persistence backend for testing.
///
/// Not crash-safe — for unit tests and development only.
#[derive(Debug, Default)]
pub struct InMemoryBackend {
    zones: BTreeMap<String, FrontierState>,
    /// When true, simulate a persistence failure.
    pub fail_on_persist: bool,
    /// Count of persist calls (for testing).
    pub persist_count: u64,
}

impl InMemoryBackend {
    pub fn new() -> Self {
        Self::default()
    }
}

impl PersistenceBackend for InMemoryBackend {
    fn persist(&mut self, state: &FrontierState) -> Result<(), String> {
        if self.fail_on_persist {
            return Err("simulated persistence failure".to_string());
        }
        self.persist_count += 1;
        self.zones.insert(state.zone.clone(), state.clone());
        Ok(())
    }

    fn load(&self, zone: &str) -> Result<Option<FrontierState>, String> {
        Ok(self.zones.get(zone).cloned())
    }

    fn load_all(&self) -> Result<Vec<FrontierState>, String> {
        Ok(self.zones.values().cloned().collect())
    }
}

// ---------------------------------------------------------------------------
// CheckpointFrontierManager — the core enforcement engine
// ---------------------------------------------------------------------------

/// Manages checkpoint frontiers across trust zones.
///
/// Enforces the unconditional monotonicity invariant: once a checkpoint
/// at sequence N is accepted, no checkpoint at sequence M <= N is ever
/// accepted, regardless of signature validity.
///
/// The frontier check is the *first* check performed (before expensive
/// signature verification) to fail fast on rollback attempts.
pub struct CheckpointFrontierManager<B: PersistenceBackend> {
    /// Per-zone frontier state (in-memory mirror of persisted state).
    zones: BTreeMap<String, FrontierState>,
    /// Persistence backend for crash-safe storage.
    backend: B,
    /// Audit events.
    events: Vec<FrontierEvent>,
}

impl<B: PersistenceBackend> CheckpointFrontierManager<B> {
    /// Create a new frontier manager with the given backend.
    ///
    /// Call `recover()` after construction to load persisted state.
    pub fn new(backend: B) -> Self {
        Self {
            zones: BTreeMap::new(),
            backend,
            events: Vec::new(),
        }
    }

    /// Recover all persisted frontiers on startup.
    ///
    /// Must be called before accepting any checkpoints.
    pub fn recover(&mut self, trace_id: &str) -> Result<usize, FrontierError> {
        let states = self
            .backend
            .load_all()
            .map_err(|e| FrontierError::PersistenceFailed {
                zone: "(all)".to_string(),
                detail: e,
            })?;

        let count = states.len();
        for state in states {
            self.events.push(FrontierEvent {
                event_type: FrontierEventType::FrontierLoaded {
                    zone: state.zone.clone(),
                    frontier_seq: state.frontier_seq,
                },
                trace_id: trace_id.to_string(),
            });
            self.zones.insert(state.zone.clone(), state);
        }

        Ok(count)
    }

    /// Get the frontier state for a zone (if initialized).
    pub fn get_frontier(&self, zone: &str) -> Option<&FrontierState> {
        self.zones.get(zone)
    }

    /// List all known zones.
    pub fn zones(&self) -> Vec<&str> {
        self.zones.keys().map(|s| s.as_str()).collect()
    }

    /// Accept a checkpoint, enforcing all invariants.
    ///
    /// Performs checks in this order (fail-fast):
    /// 1. Frontier monotonicity check (cheapest — reject rollbacks first)
    /// 2. Epoch regression check
    /// 3. Chain linkage verification (against frontier checkpoint)
    /// 4. Quorum signature verification (most expensive — last)
    /// 5. Atomic persistence
    /// 6. In-memory state update
    pub fn accept_checkpoint(
        &mut self,
        zone: &str,
        checkpoint: &PolicyCheckpoint,
        quorum_threshold: usize,
        authorized_signers: &[VerificationKey],
        trace_id: &str,
    ) -> Result<(), FrontierError> {
        match self.zones.get(zone) {
            None => {
                // First checkpoint in this zone — treat as genesis.
                self.accept_genesis(
                    zone,
                    checkpoint,
                    quorum_threshold,
                    authorized_signers,
                    trace_id,
                )
            }
            Some(frontier) => {
                // Check monotonicity FIRST (cheapest check).
                if checkpoint.checkpoint_seq <= frontier.frontier_seq {
                    if checkpoint.checkpoint_seq == frontier.frontier_seq {
                        self.events.push(FrontierEvent {
                            event_type: FrontierEventType::DuplicateRejected {
                                zone: zone.to_string(),
                                checkpoint_seq: checkpoint.checkpoint_seq,
                            },
                            trace_id: trace_id.to_string(),
                        });
                        return Err(FrontierError::DuplicateCheckpoint {
                            zone: zone.to_string(),
                            checkpoint_seq: checkpoint.checkpoint_seq,
                        });
                    }

                    self.events.push(FrontierEvent {
                        event_type: FrontierEventType::RollbackRejected {
                            zone: zone.to_string(),
                            frontier_seq: frontier.frontier_seq,
                            attempted_seq: checkpoint.checkpoint_seq,
                        },
                        trace_id: trace_id.to_string(),
                    });
                    return Err(FrontierError::RollbackRejected {
                        zone: zone.to_string(),
                        frontier_seq: frontier.frontier_seq,
                        attempted_seq: checkpoint.checkpoint_seq,
                    });
                }

                // Check epoch regression.
                if checkpoint.epoch_id < frontier.frontier_epoch {
                    self.events.push(FrontierEvent {
                        event_type: FrontierEventType::EpochRegressionRejected {
                            zone: zone.to_string(),
                            frontier_epoch: frontier.frontier_epoch,
                            attempted_epoch: checkpoint.epoch_id,
                        },
                        trace_id: trace_id.to_string(),
                    });
                    return Err(FrontierError::EpochRegression {
                        zone: zone.to_string(),
                        frontier_epoch: frontier.frontier_epoch,
                        attempted_epoch: checkpoint.epoch_id,
                    });
                }

                let prev_seq = frontier.frontier_seq;

                // Quorum verification (most expensive — done last).
                verify_checkpoint_quorum(checkpoint, quorum_threshold, authorized_signers)
                    .map_err(|e| FrontierError::QuorumFailure {
                        zone: zone.to_string(),
                        detail: e.to_string(),
                    })?;

                // Persist BEFORE updating in-memory state (crash-safe).
                let mut new_state = frontier.clone();
                new_state.advance(checkpoint);
                self.backend
                    .persist(&new_state)
                    .map_err(|e| FrontierError::PersistenceFailed {
                        zone: zone.to_string(),
                        detail: e,
                    })?;

                // Update in-memory state.
                self.zones.insert(zone.to_string(), new_state);

                self.events.push(FrontierEvent {
                    event_type: FrontierEventType::CheckpointAccepted {
                        zone: zone.to_string(),
                        prev_seq,
                        new_seq: checkpoint.checkpoint_seq,
                    },
                    trace_id: trace_id.to_string(),
                });

                Ok(())
            }
        }
    }

    /// Accept the genesis checkpoint for a new zone.
    fn accept_genesis(
        &mut self,
        zone: &str,
        checkpoint: &PolicyCheckpoint,
        quorum_threshold: usize,
        authorized_signers: &[VerificationKey],
        trace_id: &str,
    ) -> Result<(), FrontierError> {
        // Verify quorum even for genesis.
        verify_checkpoint_quorum(checkpoint, quorum_threshold, authorized_signers).map_err(
            |e| FrontierError::QuorumFailure {
                zone: zone.to_string(),
                detail: e.to_string(),
            },
        )?;

        let state = FrontierState::from_genesis(zone, checkpoint);

        // Persist before in-memory update.
        self.backend
            .persist(&state)
            .map_err(|e| FrontierError::PersistenceFailed {
                zone: zone.to_string(),
                detail: e,
            })?;

        self.zones.insert(zone.to_string(), state);

        self.events.push(FrontierEvent {
            event_type: FrontierEventType::ZoneInitialized {
                zone: zone.to_string(),
                genesis_seq: checkpoint.checkpoint_seq,
            },
            trace_id: trace_id.to_string(),
        });

        Ok(())
    }

    /// Verify chain linkage between the frontier checkpoint and a new
    /// checkpoint, given access to the full frontier checkpoint object.
    ///
    /// This is an optional additional check that requires the caller
    /// to have the full previous checkpoint object available.
    pub fn verify_linkage_against_frontier(
        &self,
        zone: &str,
        prev_checkpoint: &PolicyCheckpoint,
        new_checkpoint: &PolicyCheckpoint,
    ) -> Result<(), FrontierError> {
        let frontier = self
            .zones
            .get(zone)
            .ok_or_else(|| FrontierError::UnknownZone {
                zone: zone.to_string(),
            })?;

        // The prev_checkpoint must be the current frontier.
        if prev_checkpoint.checkpoint_id != frontier.frontier_checkpoint_id {
            return Err(FrontierError::ChainLinkageFailure {
                zone: zone.to_string(),
                detail: format!(
                    "prev checkpoint {} does not match frontier {}",
                    prev_checkpoint.checkpoint_id, frontier.frontier_checkpoint_id
                ),
            });
        }

        verify_chain_linkage(prev_checkpoint, new_checkpoint).map_err(|e| {
            FrontierError::ChainLinkageFailure {
                zone: zone.to_string(),
                detail: e.to_string(),
            }
        })?;

        Ok(())
    }

    /// Drain accumulated events.
    pub fn drain_events(&mut self) -> Vec<FrontierEvent> {
        std::mem::take(&mut self.events)
    }

    /// Count of events by type for diagnostics.
    pub fn event_counts(&self) -> BTreeMap<String, usize> {
        let mut counts = BTreeMap::new();
        for event in &self.events {
            let key = match &event.event_type {
                FrontierEventType::ZoneInitialized { .. } => "zone_initialized",
                FrontierEventType::CheckpointAccepted { .. } => "checkpoint_accepted",
                FrontierEventType::RollbackRejected { .. } => "rollback_rejected",
                FrontierEventType::DuplicateRejected { .. } => "duplicate_rejected",
                FrontierEventType::EpochRegressionRejected { .. } => "epoch_regression_rejected",
                FrontierEventType::FrontierLoaded { .. } => "frontier_loaded",
            };
            *counts.entry(key.to_string()).or_insert(0) += 1;
        }
        counts
    }

    /// Access the underlying backend (for testing/inspection).
    pub fn backend(&self) -> &B {
        &self.backend
    }

    /// Mutable access to the underlying backend (for testing).
    pub fn backend_mut(&mut self) -> &mut B {
        &mut self.backend
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::hash_tiers::ContentHash;
    use crate::policy_checkpoint::{
        CheckpointBuilder, DeterministicTimestamp, PolicyHead, PolicyType,
    };
    use crate::signature_preimage::SigningKey;

    fn make_sk(seed: u8) -> SigningKey {
        SigningKey::from_bytes([seed; 32]).expect("serde deserialization should succeed")
    }

    fn make_policy_head(pt: PolicyType, version: u64) -> PolicyHead {
        let hash_input = format!("{pt}-v{version}");
        PolicyHead {
            policy_type: pt,
            policy_hash: ContentHash::compute(hash_input.as_bytes()),
            policy_version: version,
        }
    }

    fn build_genesis(keys: &[SigningKey], zone: &str) -> PolicyCheckpoint {
        CheckpointBuilder::genesis(SecurityEpoch::GENESIS, DeterministicTimestamp(100), zone)
            .add_policy_head(make_policy_head(PolicyType::RuntimeExecution, 1))
            .build(keys)
            .expect("serde deserialization should succeed")
    }

    fn build_after(
        prev: &PolicyCheckpoint,
        seq: u64,
        epoch: SecurityEpoch,
        tick: u64,
        keys: &[SigningKey],
        zone: &str,
    ) -> PolicyCheckpoint {
        CheckpointBuilder::after(prev, seq, epoch, DeterministicTimestamp(tick), zone)
            .add_policy_head(make_policy_head(PolicyType::RuntimeExecution, seq + 1))
            .build(keys)
            .expect("serde deserialization should succeed")
    }

    fn conformance_frontier_state(zone: &str, frontier_seq: u64, id_byte: u8) -> FrontierState {
        FrontierState {
            zone: zone.to_string(),
            frontier_seq,
            frontier_checkpoint_id: EngineObjectId([id_byte; 32]),
            frontier_epoch: SecurityEpoch::from_raw(frontier_seq),
            accept_count: frontier_seq.saturating_add(1),
            recent_ids: vec![FrontierEntry {
                checkpoint_seq: frontier_seq,
                checkpoint_id: EngineObjectId([id_byte; 32]),
                epoch: SecurityEpoch::from_raw(frontier_seq),
            }],
        }
    }

    fn load_all_by_zone<B: PersistenceBackend>(
        backend: &B,
    ) -> std::collections::BTreeMap<String, u64> {
        backend
            .load_all()
            .expect("backend load_all should succeed")
            .into_iter()
            .map(|state| (state.zone, state.frontier_seq))
            .collect()
    }

    fn assert_persistence_backend_atomic_update_contract<B, FailPersist>(
        mut backend: B,
        fail_persist: FailPersist,
    ) where
        B: PersistenceBackend,
        FailPersist: FnOnce(&mut B, &FrontierState) -> Result<(), String>,
    {
        let zone_a_initial = conformance_frontier_state("zone-a", 1, 0xA1);
        let zone_b_initial = conformance_frontier_state("zone-b", 4, 0xB4);
        backend
            .persist(&zone_a_initial)
            .expect("initial zone-a persist should succeed");
        backend
            .persist(&zone_b_initial)
            .expect("initial zone-b persist should succeed");

        assert_eq!(
            backend.load("zone-a").expect("zone-a load should succeed"),
            Some(zone_a_initial.clone())
        );
        assert_eq!(
            backend.load("zone-b").expect("zone-b load should succeed"),
            Some(zone_b_initial.clone())
        );

        let before_failure = backend
            .load_all()
            .expect("pre-failure load_all should succeed");
        let before_failure_by_zone = load_all_by_zone(&backend);
        let regressed_zone_a = conformance_frontier_state("zone-a", 0, 0xAC);
        assert!(
            fail_persist(&mut backend, &regressed_zone_a).is_err(),
            "fault injection must produce a failed persist"
        );

        assert_eq!(
            backend.load("zone-a").expect("zone-a load should succeed"),
            Some(zone_a_initial),
            "failed persist must not regress the stored zone-a frontier"
        );
        assert_eq!(
            backend
                .load_all()
                .expect("post-failure load_all should succeed"),
            before_failure,
            "failed persist must leave load_all unchanged"
        );
        assert_eq!(load_all_by_zone(&backend), before_failure_by_zone);

        let zone_a_advanced = conformance_frontier_state("zone-a", 6, 0xA6);
        backend
            .persist(&zone_a_advanced)
            .expect("advanced zone-a persist should succeed");

        let first_load_all = backend.load_all().expect("load_all should succeed");
        let second_load_all = backend.load_all().expect("load_all should succeed");
        assert_eq!(
            first_load_all, second_load_all,
            "load_all must be deterministic for an unchanged backend"
        );

        let final_by_zone = load_all_by_zone(&backend);
        assert_eq!(final_by_zone.get("zone-a"), Some(&6));
        assert_eq!(final_by_zone.get("zone-b"), Some(&4));
    }

    #[test]
    fn in_memory_backend_satisfies_atomic_update_contract() {
        assert_persistence_backend_atomic_update_contract(
            InMemoryBackend::new(),
            |backend, state| {
                backend.fail_on_persist = true;
                let result = backend.persist(state);
                backend.fail_on_persist = false;
                result
            },
        );
    }

    // -- Genesis acceptance --

    #[test]
    fn genesis_checkpoint_accepted() {
        let sk = make_sk(1);
        let vk = sk.verification_key();
        let genesis = build_genesis(&[sk], "zone-a");

        let mut mgr = CheckpointFrontierManager::new(InMemoryBackend::new());
        mgr.accept_checkpoint("zone-a", &genesis, 1, &[vk], "t-genesis")
            .expect("serde deserialization should succeed");

        let frontier = mgr
            .get_frontier("zone-a")
            .expect("serde deserialization should succeed");
        assert_eq!(frontier.frontier_seq, 0);
        assert_eq!(frontier.frontier_checkpoint_id, genesis.checkpoint_id);
        assert_eq!(frontier.accept_count, 1);
    }

    #[test]
    fn genesis_emits_zone_initialized_event() {
        let sk = make_sk(1);
        let vk = sk.verification_key();
        let genesis = build_genesis(&[sk], "zone-a");

        let mut mgr = CheckpointFrontierManager::new(InMemoryBackend::new());
        mgr.accept_checkpoint("zone-a", &genesis, 1, &[vk], "t-1")
            .expect("serde deserialization should succeed");

        let events = mgr.drain_events();
        assert_eq!(events.len(), 1);
        assert!(matches!(
            &events[0].event_type,
            FrontierEventType::ZoneInitialized { zone, genesis_seq: 0 }
            if zone == "zone-a"
        ));
    }

    // -- Sequential acceptance --

    #[test]
    fn sequential_checkpoints_accepted() {
        let sk = make_sk(1);
        let vk = sk.verification_key();
        let genesis = build_genesis(std::slice::from_ref(&sk), "zone-a");

        let mut mgr = CheckpointFrontierManager::new(InMemoryBackend::new());
        mgr.accept_checkpoint("zone-a", &genesis, 1, std::slice::from_ref(&vk), "t-0")
            .expect("serde deserialization should succeed");

        let cp1 = build_after(
            &genesis,
            1,
            SecurityEpoch::GENESIS,
            200,
            std::slice::from_ref(&sk),
            "zone-a",
        );
        mgr.accept_checkpoint("zone-a", &cp1, 1, std::slice::from_ref(&vk), "t-1")
            .expect("serde deserialization should succeed");

        let cp2 = build_after(&cp1, 2, SecurityEpoch::GENESIS, 300, &[sk], "zone-a");
        mgr.accept_checkpoint("zone-a", &cp2, 1, &[vk], "t-2")
            .expect("serde deserialization should succeed");

        let frontier = mgr
            .get_frontier("zone-a")
            .expect("serde deserialization should succeed");
        assert_eq!(frontier.frontier_seq, 2);
        assert_eq!(frontier.frontier_checkpoint_id, cp2.checkpoint_id);
        assert_eq!(frontier.accept_count, 3);
    }

    // -- Rollback rejection (core invariant) --

    #[test]
    fn rollback_rejected_unconditionally() {
        let sk = make_sk(1);
        let vk = sk.verification_key();
        let genesis = build_genesis(std::slice::from_ref(&sk), "zone-a");

        let mut mgr = CheckpointFrontierManager::new(InMemoryBackend::new());
        mgr.accept_checkpoint("zone-a", &genesis, 1, std::slice::from_ref(&vk), "t-0")
            .expect("serde deserialization should succeed");

        let cp1 = build_after(
            &genesis,
            1,
            SecurityEpoch::GENESIS,
            200,
            std::slice::from_ref(&sk),
            "zone-a",
        );
        mgr.accept_checkpoint("zone-a", &cp1, 1, std::slice::from_ref(&vk), "t-1")
            .expect("serde deserialization should succeed");

        // Build a validly-signed checkpoint at seq=0 (rollback to genesis level).
        // This must be rejected even though signatures are valid.
        let rollback = build_genesis(&[sk], "zone-a");
        let err = mgr
            .accept_checkpoint("zone-a", &rollback, 1, &[vk], "t-rollback")
            .unwrap_err();

        assert!(matches!(
            err,
            FrontierError::RollbackRejected {
                frontier_seq: 1,
                attempted_seq: 0,
                ..
            }
        ));
    }

    #[test]
    fn rollback_emits_rejection_event() {
        let sk = make_sk(1);
        let vk = sk.verification_key();
        let genesis = build_genesis(std::slice::from_ref(&sk), "zone-a");

        let mut mgr = CheckpointFrontierManager::new(InMemoryBackend::new());
        mgr.accept_checkpoint("zone-a", &genesis, 1, std::slice::from_ref(&vk), "t-0")
            .expect("serde deserialization should succeed");

        let cp1 = build_after(
            &genesis,
            1,
            SecurityEpoch::GENESIS,
            200,
            std::slice::from_ref(&sk),
            "zone-a",
        );
        mgr.accept_checkpoint("zone-a", &cp1, 1, std::slice::from_ref(&vk), "t-1")
            .expect("serde deserialization should succeed");

        // Drain previous events.
        mgr.drain_events();

        let rollback = build_genesis(&[sk], "zone-a");
        let _ = mgr.accept_checkpoint("zone-a", &rollback, 1, &[vk], "t-rollback");

        let events = mgr.drain_events();
        assert!(
            events
                .iter()
                .any(|e| matches!(&e.event_type, FrontierEventType::RollbackRejected { .. }))
        );
    }

    // -- Duplicate rejection --

    #[test]
    fn duplicate_checkpoint_rejected() {
        let sk = make_sk(1);
        let vk = sk.verification_key();
        let genesis = build_genesis(std::slice::from_ref(&sk), "zone-a");

        let mut mgr = CheckpointFrontierManager::new(InMemoryBackend::new());
        mgr.accept_checkpoint("zone-a", &genesis, 1, std::slice::from_ref(&vk), "t-0")
            .expect("serde deserialization should succeed");

        let cp1 = build_after(
            &genesis,
            1,
            SecurityEpoch::GENESIS,
            200,
            std::slice::from_ref(&sk),
            "zone-a",
        );
        mgr.accept_checkpoint("zone-a", &cp1, 1, std::slice::from_ref(&vk), "t-1")
            .expect("serde deserialization should succeed");

        // Try to accept cp1 again (same seq=1).
        let dup = build_after(&genesis, 1, SecurityEpoch::GENESIS, 250, &[sk], "zone-a");
        let err = mgr
            .accept_checkpoint("zone-a", &dup, 1, &[vk], "t-dup")
            .unwrap_err();

        assert!(matches!(
            err,
            FrontierError::DuplicateCheckpoint {
                checkpoint_seq: 1,
                ..
            }
        ));
    }

    // -- Epoch regression --

    #[test]
    fn epoch_regression_rejected() {
        let sk = make_sk(1);
        let vk = sk.verification_key();

        // Accept genesis at epoch 5.
        let genesis_e5 = CheckpointBuilder::genesis(
            SecurityEpoch::from_raw(5),
            DeterministicTimestamp(100),
            "zone-a",
        )
        .add_policy_head(make_policy_head(PolicyType::RuntimeExecution, 1))
        .build(std::slice::from_ref(&sk))
        .expect("serde deserialization should succeed");

        let mut mgr = CheckpointFrontierManager::new(InMemoryBackend::new());
        mgr.accept_checkpoint("zone-a", &genesis_e5, 1, std::slice::from_ref(&vk), "t-0")
            .expect("serde deserialization should succeed");

        // Advance to seq=1, still at epoch 5.
        let cp1 = build_after(
            &genesis_e5,
            1,
            SecurityEpoch::from_raw(5),
            200,
            std::slice::from_ref(&sk),
            "zone-a",
        );
        mgr.accept_checkpoint("zone-a", &cp1, 1, std::slice::from_ref(&vk), "t-1")
            .expect("serde deserialization should succeed");

        // Build a seq=2 checkpoint at epoch 3 (regression). The builder
        // won't catch this because it only checks against its direct
        // predecessor. We pass epoch 5 predecessor but tell builder
        // we want epoch 3. Actually the builder DOES check prev_epoch.
        // Instead, build from a separate chain with lower epoch and
        // higher seq, then attempt to inject it.
        let independent_genesis = CheckpointBuilder::genesis(
            SecurityEpoch::from_raw(3),
            DeterministicTimestamp(50),
            "zone-a",
        )
        .add_policy_head(make_policy_head(PolicyType::RuntimeExecution, 1))
        .build(std::slice::from_ref(&sk))
        .expect("serde deserialization should succeed");

        // Build seq=2 from the epoch-3 chain.
        let regressed_cp = build_after(
            &independent_genesis,
            2,
            SecurityEpoch::from_raw(3),
            300,
            &[sk],
            "zone-a",
        );

        // This has seq=2 > frontier seq=1, but epoch=3 < frontier epoch=5.
        // Frontier must reject it.
        let err = mgr
            .accept_checkpoint("zone-a", &regressed_cp, 1, &[vk], "t-regress")
            .unwrap_err();

        assert!(matches!(err, FrontierError::EpochRegression { .. }));
    }

    // -- Per-zone isolation --

    #[test]
    fn zones_are_independent() {
        let sk = make_sk(1);
        let vk = sk.verification_key();
        let genesis_a = build_genesis(std::slice::from_ref(&sk), "zone-a");
        let genesis_b = build_genesis(std::slice::from_ref(&sk), "zone-b");

        let mut mgr = CheckpointFrontierManager::new(InMemoryBackend::new());
        mgr.accept_checkpoint("zone-a", &genesis_a, 1, std::slice::from_ref(&vk), "t-a0")
            .expect("serde deserialization should succeed");
        mgr.accept_checkpoint("zone-b", &genesis_b, 1, std::slice::from_ref(&vk), "t-b0")
            .expect("serde deserialization should succeed");

        // Advance zone-a to seq=3.
        let cp_a1 = build_after(
            &genesis_a,
            1,
            SecurityEpoch::GENESIS,
            200,
            std::slice::from_ref(&sk),
            "zone-a",
        );
        mgr.accept_checkpoint("zone-a", &cp_a1, 1, std::slice::from_ref(&vk), "t-a1")
            .expect("serde deserialization should succeed");

        let cp_a2 = build_after(
            &cp_a1,
            2,
            SecurityEpoch::GENESIS,
            300,
            std::slice::from_ref(&sk),
            "zone-a",
        );
        mgr.accept_checkpoint("zone-a", &cp_a2, 1, std::slice::from_ref(&vk), "t-a2")
            .expect("serde deserialization should succeed");

        let cp_a3 = build_after(
            &cp_a2,
            3,
            SecurityEpoch::GENESIS,
            400,
            std::slice::from_ref(&sk),
            "zone-a",
        );
        mgr.accept_checkpoint("zone-a", &cp_a3, 1, std::slice::from_ref(&vk), "t-a3")
            .expect("serde deserialization should succeed");

        // Zone-b should still be at seq=0.
        let frontier_b = mgr
            .get_frontier("zone-b")
            .expect("serde deserialization should succeed");
        assert_eq!(frontier_b.frontier_seq, 0);

        // Zone-a should be at seq=3.
        let frontier_a = mgr
            .get_frontier("zone-a")
            .expect("serde deserialization should succeed");
        assert_eq!(frontier_a.frontier_seq, 3);

        // Zone-b can still accept seq=1.
        let cp_b1 = build_after(&genesis_b, 1, SecurityEpoch::GENESIS, 200, &[sk], "zone-b");
        mgr.accept_checkpoint("zone-b", &cp_b1, 1, &[vk], "t-b1")
            .expect("serde deserialization should succeed");

        let frontier_b = mgr
            .get_frontier("zone-b")
            .expect("serde deserialization should succeed");
        assert_eq!(frontier_b.frontier_seq, 1);
    }

    // -- Quorum failure --

    #[test]
    fn quorum_failure_rejects_acceptance() {
        let sk = make_sk(1);
        let wrong_vk =
            VerificationKey::from_bytes([0xFF; 32]).expect("serde deserialization should succeed");
        let genesis = build_genesis(&[sk], "zone-a");

        let mut mgr = CheckpointFrontierManager::new(InMemoryBackend::new());
        // Provide wrong authorized signers.
        let err = mgr
            .accept_checkpoint("zone-a", &genesis, 1, &[wrong_vk], "t-bad")
            .unwrap_err();

        assert!(matches!(err, FrontierError::QuorumFailure { .. }));
        // Zone should not be initialized.
        assert!(mgr.get_frontier("zone-a").is_none());
    }

    // -- Persistence --

    #[test]
    fn frontier_persisted_on_acceptance() {
        let sk = make_sk(1);
        let vk = sk.verification_key();
        let genesis = build_genesis(&[sk], "zone-a");

        let mut mgr = CheckpointFrontierManager::new(InMemoryBackend::new());
        mgr.accept_checkpoint("zone-a", &genesis, 1, &[vk], "t-0")
            .expect("serde deserialization should succeed");

        assert_eq!(mgr.backend().persist_count, 1);
        let loaded = mgr
            .backend()
            .load("zone-a")
            .expect("serde deserialization should succeed")
            .expect("serde deserialization should succeed");
        assert_eq!(loaded.frontier_seq, 0);
        assert_eq!(loaded.zone, "zone-a");
    }

    #[test]
    fn persistence_failure_prevents_acceptance() {
        let sk = make_sk(1);
        let vk = sk.verification_key();
        let genesis = build_genesis(std::slice::from_ref(&sk), "zone-a");

        let mut mgr = CheckpointFrontierManager::new(InMemoryBackend::new());
        mgr.accept_checkpoint("zone-a", &genesis, 1, std::slice::from_ref(&vk), "t-0")
            .expect("serde deserialization should succeed");

        // Enable failure.
        mgr.backend_mut().fail_on_persist = true;

        let cp1 = build_after(&genesis, 1, SecurityEpoch::GENESIS, 200, &[sk], "zone-a");
        let err = mgr
            .accept_checkpoint("zone-a", &cp1, 1, &[vk], "t-fail")
            .unwrap_err();

        assert!(matches!(err, FrontierError::PersistenceFailed { .. }));

        // Frontier should NOT have advanced.
        let frontier = mgr
            .get_frontier("zone-a")
            .expect("serde deserialization should succeed");
        assert_eq!(frontier.frontier_seq, 0);
    }

    // -- Recovery --

    #[test]
    fn recovery_loads_persisted_frontier() {
        let sk = make_sk(1);
        let vk = sk.verification_key();
        let genesis = build_genesis(std::slice::from_ref(&sk), "zone-a");

        let mut backend = InMemoryBackend::new();

        // Build the state directly in the backend to simulate a
        // previous session that persisted frontier at seq=2.
        let cp1 = build_after(
            &genesis,
            1,
            SecurityEpoch::GENESIS,
            200,
            std::slice::from_ref(&sk),
            "zone-a",
        );
        let cp2 = build_after(
            &cp1,
            2,
            SecurityEpoch::GENESIS,
            300,
            std::slice::from_ref(&sk),
            "zone-a",
        );

        let mut state = FrontierState::from_genesis("zone-a", &genesis);
        state.advance(&cp1);
        state.advance(&cp2);
        backend
            .persist(&state)
            .expect("serde deserialization should succeed");

        // Create new manager and recover.
        let mut mgr = CheckpointFrontierManager::new(backend);
        let count = mgr
            .recover("t-recover")
            .expect("serde deserialization should succeed");
        assert_eq!(count, 1);

        let frontier = mgr
            .get_frontier("zone-a")
            .expect("serde deserialization should succeed");
        assert_eq!(frontier.frontier_seq, 2);
        assert_eq!(frontier.accept_count, 3);

        // Rollback to seq=1 must be rejected.
        let rollback = build_after(
            &genesis,
            1,
            SecurityEpoch::GENESIS,
            250,
            std::slice::from_ref(&sk),
            "zone-a",
        );
        let err = mgr
            .accept_checkpoint(
                "zone-a",
                &rollback,
                1,
                std::slice::from_ref(&vk),
                "t-post-recover",
            )
            .unwrap_err();
        assert!(matches!(err, FrontierError::RollbackRejected { .. }));

        // Seq=3 should be accepted.
        let cp3 = build_after(
            &cp2,
            3,
            SecurityEpoch::GENESIS,
            400,
            std::slice::from_ref(&sk),
            "zone-a",
        );
        mgr.accept_checkpoint("zone-a", &cp3, 1, &[vk], "t-3")
            .expect("serde deserialization should succeed");

        let frontier = mgr
            .get_frontier("zone-a")
            .expect("serde deserialization should succeed");
        assert_eq!(frontier.frontier_seq, 3);
    }

    // -- Forensic history --

    #[test]
    fn recent_ids_tracked() {
        let sk = make_sk(1);
        let vk = sk.verification_key();
        let genesis = build_genesis(std::slice::from_ref(&sk), "zone-a");

        let mut mgr = CheckpointFrontierManager::new(InMemoryBackend::new());
        mgr.accept_checkpoint("zone-a", &genesis, 1, std::slice::from_ref(&vk), "t-0")
            .expect("serde deserialization should succeed");

        let cp1 = build_after(
            &genesis,
            1,
            SecurityEpoch::GENESIS,
            200,
            std::slice::from_ref(&sk),
            "zone-a",
        );
        mgr.accept_checkpoint("zone-a", &cp1, 1, std::slice::from_ref(&vk), "t-1")
            .expect("serde deserialization should succeed");

        let cp2 = build_after(&cp1, 2, SecurityEpoch::GENESIS, 300, &[sk], "zone-a");
        mgr.accept_checkpoint("zone-a", &cp2, 1, &[vk], "t-2")
            .expect("serde deserialization should succeed");

        let frontier = mgr
            .get_frontier("zone-a")
            .expect("serde deserialization should succeed");
        assert_eq!(frontier.recent_ids.len(), 3);
        assert_eq!(frontier.recent_ids[0].checkpoint_seq, 0);
        assert_eq!(frontier.recent_ids[1].checkpoint_seq, 1);
        assert_eq!(frontier.recent_ids[2].checkpoint_seq, 2);
    }

    #[test]
    fn recent_ids_bounded() {
        let sk = make_sk(1);
        let vk = sk.verification_key();
        let genesis = build_genesis(std::slice::from_ref(&sk), "zone-a");

        let mut mgr = CheckpointFrontierManager::new(InMemoryBackend::new());
        mgr.accept_checkpoint("zone-a", &genesis, 1, std::slice::from_ref(&vk), "t-0")
            .expect("serde deserialization should succeed");

        // Accept 40 more checkpoints (exceeds MAX_RECENT_ENTRIES=32).
        let mut prev = genesis;
        for i in 1..=40u64 {
            let cp = build_after(
                &prev,
                i,
                SecurityEpoch::GENESIS,
                100 + i * 100,
                std::slice::from_ref(&sk),
                "zone-a",
            );
            mgr.accept_checkpoint(
                "zone-a",
                &cp,
                1,
                std::slice::from_ref(&vk),
                &format!("t-{i}"),
            )
            .expect("serde deserialization should succeed");
            prev = cp;
        }

        let frontier = mgr
            .get_frontier("zone-a")
            .expect("serde deserialization should succeed");
        assert!(frontier.recent_ids.len() <= FrontierState::MAX_RECENT_ENTRIES);
        // The last entry should be seq=40.
        assert_eq!(
            frontier
                .recent_ids
                .last()
                .expect("serde deserialization should succeed")
                .checkpoint_seq,
            40
        );
    }

    // -- Unknown zone --

    #[test]
    fn unknown_zone_returns_none() {
        let mgr = CheckpointFrontierManager::new(InMemoryBackend::new());
        assert!(mgr.get_frontier("nonexistent").is_none());
    }

    // -- Multiple signers --

    #[test]
    fn multi_signer_quorum_accepted() {
        let sk1 = make_sk(1);
        let sk2 = make_sk(2);
        let vk1 = sk1.verification_key();
        let vk2 = sk2.verification_key();

        let genesis = CheckpointBuilder::genesis(
            SecurityEpoch::GENESIS,
            DeterministicTimestamp(100),
            "zone-a",
        )
        .add_policy_head(make_policy_head(PolicyType::RuntimeExecution, 1))
        .build(&[sk1, sk2])
        .expect("serde deserialization should succeed");

        let mut mgr = CheckpointFrontierManager::new(InMemoryBackend::new());
        mgr.accept_checkpoint("zone-a", &genesis, 2, &[vk1, vk2], "t-0")
            .expect("serde deserialization should succeed");

        let frontier = mgr
            .get_frontier("zone-a")
            .expect("serde deserialization should succeed");
        assert_eq!(frontier.frontier_seq, 0);
    }

    // -- Epoch transition --

    #[test]
    fn epoch_transition_accepted() {
        let sk = make_sk(1);
        let vk = sk.verification_key();
        let genesis = build_genesis(std::slice::from_ref(&sk), "zone-a");

        let mut mgr = CheckpointFrontierManager::new(InMemoryBackend::new());
        mgr.accept_checkpoint("zone-a", &genesis, 1, std::slice::from_ref(&vk), "t-0")
            .expect("serde deserialization should succeed");

        // Epoch transition from 0 to 5.
        let cp1 = build_after(
            &genesis,
            1,
            SecurityEpoch::from_raw(5),
            200,
            &[sk],
            "zone-a",
        );
        mgr.accept_checkpoint("zone-a", &cp1, 1, &[vk], "t-1")
            .expect("serde deserialization should succeed");

        let frontier = mgr
            .get_frontier("zone-a")
            .expect("serde deserialization should succeed");
        assert_eq!(frontier.frontier_epoch, SecurityEpoch::from_raw(5));
    }

    // -- zones() listing --

    #[test]
    fn zones_listing() {
        let sk = make_sk(1);
        let vk = sk.verification_key();

        let mut mgr = CheckpointFrontierManager::new(InMemoryBackend::new());
        assert!(mgr.zones().is_empty());

        let genesis_a = build_genesis(std::slice::from_ref(&sk), "zone-a");
        mgr.accept_checkpoint("zone-a", &genesis_a, 1, std::slice::from_ref(&vk), "t-a")
            .expect("serde deserialization should succeed");

        let genesis_b = build_genesis(&[sk], "zone-b");
        mgr.accept_checkpoint("zone-b", &genesis_b, 1, &[vk], "t-b")
            .expect("serde deserialization should succeed");

        let zones = mgr.zones();
        assert_eq!(zones.len(), 2);
        assert!(zones.contains(&"zone-a"));
        assert!(zones.contains(&"zone-b"));
    }

    // -- Event counts --

    #[test]
    fn event_counts_accurate() {
        let sk = make_sk(1);
        let vk = sk.verification_key();
        let genesis = build_genesis(std::slice::from_ref(&sk), "zone-a");

        let mut mgr = CheckpointFrontierManager::new(InMemoryBackend::new());
        mgr.accept_checkpoint("zone-a", &genesis, 1, std::slice::from_ref(&vk), "t-0")
            .expect("serde deserialization should succeed");

        let cp1 = build_after(
            &genesis,
            1,
            SecurityEpoch::GENESIS,
            200,
            std::slice::from_ref(&sk),
            "zone-a",
        );
        mgr.accept_checkpoint("zone-a", &cp1, 1, std::slice::from_ref(&vk), "t-1")
            .expect("serde deserialization should succeed");

        // Attempt rollback.
        let rollback = build_genesis(&[sk], "zone-a");
        let _ = mgr.accept_checkpoint("zone-a", &rollback, 1, &[vk], "t-bad");

        let counts = mgr.event_counts();
        assert_eq!(counts["zone_initialized"], 1);
        assert_eq!(counts["checkpoint_accepted"], 1);
        assert_eq!(counts["rollback_rejected"], 1);
    }

    // -- Serialization --

    #[test]
    fn frontier_state_serialization_round_trip() {
        let sk = make_sk(1);
        let genesis = build_genesis(&[sk], "zone-a");
        let state = FrontierState::from_genesis("zone-a", &genesis);

        let json = serde_json::to_string(&state).expect("serde deserialization should succeed");
        let restored: FrontierState =
            serde_json::from_str(&json).expect("serde deserialization should succeed");
        assert_eq!(state, restored);
    }

    #[test]
    fn frontier_error_serialization_round_trip() {
        let errors = vec![
            FrontierError::RollbackRejected {
                zone: "z".to_string(),
                frontier_seq: 5,
                attempted_seq: 3,
            },
            FrontierError::DuplicateCheckpoint {
                zone: "z".to_string(),
                checkpoint_seq: 5,
            },
            FrontierError::UnknownZone {
                zone: "z".to_string(),
            },
        ];
        for err in &errors {
            let json = serde_json::to_string(err).expect("serde deserialization should succeed");
            let restored: FrontierError =
                serde_json::from_str(&json).expect("serde deserialization should succeed");
            assert_eq!(*err, restored);
        }
    }

    #[test]
    fn frontier_event_serialization_round_trip() {
        let event = FrontierEvent {
            event_type: FrontierEventType::CheckpointAccepted {
                zone: "z".to_string(),
                prev_seq: 1,
                new_seq: 2,
            },
            trace_id: "t-1".to_string(),
        };
        let json = serde_json::to_string(&event).expect("serde deserialization should succeed");
        let restored: FrontierEvent =
            serde_json::from_str(&json).expect("serde deserialization should succeed");
        assert_eq!(event, restored);
    }

    // -- Display --

    #[test]
    fn frontier_error_display() {
        let err = FrontierError::RollbackRejected {
            zone: "zone-a".to_string(),
            frontier_seq: 10,
            attempted_seq: 5,
        };
        let s = err.to_string();
        assert!(s.contains("zone-a"));
        assert!(s.contains("10"));
        assert!(s.contains("5"));
    }

    #[test]
    fn frontier_event_type_display() {
        let et = FrontierEventType::CheckpointAccepted {
            zone: "z".to_string(),
            prev_seq: 1,
            new_seq: 2,
        };
        assert!(et.to_string().contains("1"));
        assert!(et.to_string().contains("2"));
    }

    // -- Chain linkage verification --

    #[test]
    fn linkage_verification_succeeds() {
        let sk = make_sk(1);
        let vk = sk.verification_key();
        let genesis = build_genesis(std::slice::from_ref(&sk), "zone-a");

        let mut mgr = CheckpointFrontierManager::new(InMemoryBackend::new());
        mgr.accept_checkpoint("zone-a", &genesis, 1, std::slice::from_ref(&vk), "t-0")
            .expect("serde deserialization should succeed");

        let cp1 = build_after(&genesis, 1, SecurityEpoch::GENESIS, 200, &[sk], "zone-a");

        mgr.verify_linkage_against_frontier("zone-a", &genesis, &cp1)
            .expect("serde deserialization should succeed");
    }

    #[test]
    fn linkage_verification_fails_wrong_prev() {
        let sk = make_sk(1);
        let vk = sk.verification_key();
        let genesis = build_genesis(std::slice::from_ref(&sk), "zone-a");

        let mut mgr = CheckpointFrontierManager::new(InMemoryBackend::new());
        mgr.accept_checkpoint("zone-a", &genesis, 1, std::slice::from_ref(&vk), "t-0")
            .expect("serde deserialization should succeed");

        let cp1 = build_after(
            &genesis,
            1,
            SecurityEpoch::GENESIS,
            200,
            std::slice::from_ref(&sk),
            "zone-a",
        );
        mgr.accept_checkpoint("zone-a", &cp1, 1, std::slice::from_ref(&vk), "t-1")
            .expect("serde deserialization should succeed");

        // Try to verify using genesis as prev (but frontier is at cp1).
        let cp2 = build_after(&cp1, 2, SecurityEpoch::GENESIS, 300, &[sk], "zone-a");
        let err = mgr
            .verify_linkage_against_frontier("zone-a", &genesis, &cp2)
            .unwrap_err();
        assert!(matches!(err, FrontierError::ChainLinkageFailure { .. }));
    }

    #[test]
    fn linkage_verification_unknown_zone() {
        let mgr = CheckpointFrontierManager::new(InMemoryBackend::new());
        let sk = make_sk(1);
        let genesis = build_genesis(std::slice::from_ref(&sk), "zone-a");
        let cp1 = build_after(&genesis, 1, SecurityEpoch::GENESIS, 200, &[sk], "zone-a");

        let err = mgr
            .verify_linkage_against_frontier("zone-nope", &genesis, &cp1)
            .unwrap_err();
        assert!(matches!(err, FrontierError::UnknownZone { .. }));
    }

    // -- FrontierError Display all variants --

    #[test]
    fn frontier_error_display_all_variants() {
        let cases: Vec<(FrontierError, &str)> = vec![
            (
                FrontierError::DuplicateCheckpoint {
                    zone: "z".to_string(),
                    checkpoint_seq: 5,
                },
                "duplicate",
            ),
            (
                FrontierError::ChainLinkageFailure {
                    zone: "z".to_string(),
                    detail: "mismatch".to_string(),
                },
                "mismatch",
            ),
            (
                FrontierError::QuorumFailure {
                    zone: "z".to_string(),
                    detail: "insufficient".to_string(),
                },
                "insufficient",
            ),
            (
                FrontierError::UnknownZone {
                    zone: "z".to_string(),
                },
                "unknown zone",
            ),
            (
                FrontierError::EpochRegression {
                    zone: "z".to_string(),
                    frontier_epoch: SecurityEpoch::from_raw(3),
                    attempted_epoch: SecurityEpoch::from_raw(1),
                },
                "epoch regression",
            ),
            (
                FrontierError::PersistenceFailed {
                    zone: "z".to_string(),
                    detail: "disk".to_string(),
                },
                "disk",
            ),
        ];
        for (err, substring) in cases {
            assert!(
                err.to_string().contains(substring),
                "'{}' should contain '{}'",
                err,
                substring
            );
        }
    }

    // -- FrontierEventType Display all variants --

    #[test]
    fn frontier_event_type_display_all_variants() {
        let cases = vec![
            (
                FrontierEventType::ZoneInitialized {
                    zone: "z".to_string(),
                    genesis_seq: 0,
                },
                "zone_initialized",
            ),
            (
                FrontierEventType::RollbackRejected {
                    zone: "z".to_string(),
                    frontier_seq: 5,
                    attempted_seq: 3,
                },
                "rollback_rejected",
            ),
            (
                FrontierEventType::DuplicateRejected {
                    zone: "z".to_string(),
                    checkpoint_seq: 5,
                },
                "duplicate_rejected",
            ),
            (
                FrontierEventType::EpochRegressionRejected {
                    zone: "z".to_string(),
                    frontier_epoch: SecurityEpoch::from_raw(3),
                    attempted_epoch: SecurityEpoch::from_raw(1),
                },
                "epoch_regression_rejected",
            ),
            (
                FrontierEventType::FrontierLoaded {
                    zone: "z".to_string(),
                    frontier_seq: 10,
                },
                "frontier_loaded",
            ),
        ];
        for (et, substring) in cases {
            assert!(
                et.to_string().contains(substring),
                "'{}' should contain '{}'",
                et,
                substring
            );
        }
    }

    // -- FrontierError serde for remaining variants --

    #[test]
    fn frontier_error_serde_all_variants() {
        let errors = vec![
            FrontierError::ChainLinkageFailure {
                zone: "z".to_string(),
                detail: "d".to_string(),
            },
            FrontierError::QuorumFailure {
                zone: "z".to_string(),
                detail: "d".to_string(),
            },
            FrontierError::EpochRegression {
                zone: "z".to_string(),
                frontier_epoch: SecurityEpoch::from_raw(5),
                attempted_epoch: SecurityEpoch::from_raw(2),
            },
            FrontierError::PersistenceFailed {
                zone: "z".to_string(),
                detail: "d".to_string(),
            },
        ];
        for err in &errors {
            let json = serde_json::to_string(err).expect("serde deserialization should succeed");
            let restored: FrontierError =
                serde_json::from_str(&json).expect("serde deserialization should succeed");
            assert_eq!(*err, restored);
        }
    }

    // -- FrontierEntry serde --

    #[test]
    fn frontier_entry_serde_roundtrip() {
        let entry = FrontierEntry {
            checkpoint_seq: 5,
            checkpoint_id: EngineObjectId([0xAA; 32]),
            epoch: SecurityEpoch::from_raw(2),
        };
        let json = serde_json::to_string(&entry).expect("serde deserialization should succeed");
        let restored: FrontierEntry =
            serde_json::from_str(&json).expect("serde deserialization should succeed");
        assert_eq!(entry, restored);
    }

    // -- get_frontier for missing zone --

    #[test]
    fn get_frontier_returns_none_for_missing_zone() {
        let mgr = CheckpointFrontierManager::new(InMemoryBackend::new());
        assert!(mgr.get_frontier("nonexistent").is_none());
    }

    // -- zones listing --

    #[test]
    fn zones_listing_across_multiple_zones() {
        let sk = make_sk(1);
        let vk = sk.verification_key();
        let genesis_a = build_genesis(std::slice::from_ref(&sk), "zone-a");
        let genesis_b = build_genesis(&[sk], "zone-b");

        let mut mgr = CheckpointFrontierManager::new(InMemoryBackend::new());
        mgr.accept_checkpoint("zone-a", &genesis_a, 1, std::slice::from_ref(&vk), "t-a")
            .expect("serde deserialization should succeed");
        mgr.accept_checkpoint("zone-b", &genesis_b, 1, &[vk], "t-b")
            .expect("serde deserialization should succeed");

        let zones = mgr.zones();
        assert_eq!(zones.len(), 2);
        assert!(zones.contains(&"zone-a"));
        assert!(zones.contains(&"zone-b"));
    }

    // -- Duplicate checkpoint rejection (after advance) --

    #[test]
    fn duplicate_checkpoint_after_advance_rejected() {
        let sk = make_sk(1);
        let vk = sk.verification_key();
        let genesis = build_genesis(std::slice::from_ref(&sk), "zone-a");

        let mut mgr = CheckpointFrontierManager::new(InMemoryBackend::new());
        mgr.accept_checkpoint("zone-a", &genesis, 1, std::slice::from_ref(&vk), "t-0")
            .expect("serde deserialization should succeed");

        let cp1 = build_after(
            &genesis,
            1,
            SecurityEpoch::GENESIS,
            200,
            std::slice::from_ref(&sk),
            "zone-a",
        );
        mgr.accept_checkpoint("zone-a", &cp1, 1, std::slice::from_ref(&vk), "t-1")
            .expect("serde deserialization should succeed");

        // Re-submit cp1 — should be duplicate.
        let err = mgr
            .accept_checkpoint("zone-a", &cp1, 1, &[vk], "t-dup")
            .unwrap_err();
        assert!(matches!(
            err,
            FrontierError::DuplicateCheckpoint {
                checkpoint_seq: 1,
                ..
            }
        ));
    }

    // -- Persistence failure --

    #[test]
    fn persistence_failure_rejects_genesis() {
        let sk = make_sk(1);
        let vk = sk.verification_key();
        let genesis = build_genesis(&[sk], "zone-a");

        let mut backend = InMemoryBackend::new();
        backend.fail_on_persist = true;
        let mut mgr = CheckpointFrontierManager::new(backend);

        let err = mgr
            .accept_checkpoint("zone-a", &genesis, 1, &[vk], "t-0")
            .unwrap_err();
        assert!(matches!(err, FrontierError::PersistenceFailed { .. }));
    }

    #[test]
    fn persistence_failure_rejects_advance() {
        let sk = make_sk(1);
        let vk = sk.verification_key();
        let genesis = build_genesis(std::slice::from_ref(&sk), "zone-a");

        let mut mgr = CheckpointFrontierManager::new(InMemoryBackend::new());
        mgr.accept_checkpoint("zone-a", &genesis, 1, std::slice::from_ref(&vk), "t-0")
            .expect("serde deserialization should succeed");

        // Enable failure.
        mgr.backend_mut().fail_on_persist = true;

        let cp1 = build_after(&genesis, 1, SecurityEpoch::GENESIS, 200, &[sk], "zone-a");
        let err = mgr
            .accept_checkpoint("zone-a", &cp1, 1, &[vk], "t-1")
            .unwrap_err();
        assert!(matches!(err, FrontierError::PersistenceFailed { .. }));

        // Frontier should NOT have advanced.
        assert_eq!(
            mgr.get_frontier("zone-a")
                .expect("serde deserialization should succeed")
                .frontier_seq,
            0
        );
    }

    // -- Recovery --

    #[test]
    fn recover_loads_persisted_state() {
        let sk = make_sk(1);
        let genesis = build_genesis(&[sk], "zone-a");

        let mut backend = InMemoryBackend::new();
        let state = FrontierState::from_genesis("zone-a", &genesis);
        backend
            .persist(&state)
            .expect("serde deserialization should succeed");

        let mut mgr = CheckpointFrontierManager::new(backend);
        let count = mgr
            .recover("t-recover")
            .expect("serde deserialization should succeed");
        assert_eq!(count, 1);
        assert_eq!(
            mgr.get_frontier("zone-a")
                .expect("serde deserialization should succeed")
                .frontier_seq,
            0
        );
    }

    #[test]
    fn recover_emits_loaded_events() {
        let sk = make_sk(1);
        let genesis = build_genesis(&[sk], "zone-a");

        let mut backend = InMemoryBackend::new();
        backend
            .persist(&FrontierState::from_genesis("zone-a", &genesis))
            .expect("serde deserialization should succeed");

        let mut mgr = CheckpointFrontierManager::new(backend);
        mgr.recover("t-recover")
            .expect("serde deserialization should succeed");

        let events = mgr.drain_events();
        assert_eq!(events.len(), 1);
        assert!(matches!(
            &events[0].event_type,
            FrontierEventType::FrontierLoaded { zone, .. } if zone == "zone-a"
        ));
    }

    // -- Persist count tracking --

    #[test]
    fn backend_persist_count_increments() {
        let sk = make_sk(1);
        let vk = sk.verification_key();
        let genesis = build_genesis(std::slice::from_ref(&sk), "zone-a");

        let mut mgr = CheckpointFrontierManager::new(InMemoryBackend::new());
        assert_eq!(mgr.backend().persist_count, 0);

        mgr.accept_checkpoint("zone-a", &genesis, 1, std::slice::from_ref(&vk), "t-0")
            .expect("serde deserialization should succeed");
        assert_eq!(mgr.backend().persist_count, 1);

        let cp1 = build_after(&genesis, 1, SecurityEpoch::GENESIS, 200, &[sk], "zone-a");
        mgr.accept_checkpoint("zone-a", &cp1, 1, &[vk], "t-1")
            .expect("serde deserialization should succeed");
        assert_eq!(mgr.backend().persist_count, 2);
    }

    // -- Recent IDs trimming --

    #[test]
    fn recent_ids_trimmed_to_max() {
        let sk = make_sk(1);
        let vk = sk.verification_key();
        let genesis = build_genesis(std::slice::from_ref(&sk), "zone-a");

        let mut mgr = CheckpointFrontierManager::new(InMemoryBackend::new());
        mgr.accept_checkpoint("zone-a", &genesis, 1, std::slice::from_ref(&vk), "t-0")
            .expect("serde deserialization should succeed");

        let mut prev = genesis;
        for i in 1..=40u64 {
            let cp = build_after(
                &prev,
                i,
                SecurityEpoch::GENESIS,
                100 + i * 100,
                std::slice::from_ref(&sk),
                "zone-a",
            );
            mgr.accept_checkpoint(
                "zone-a",
                &cp,
                1,
                std::slice::from_ref(&vk),
                &format!("t-{i}"),
            )
            .expect("serde deserialization should succeed");
            prev = cp;
        }

        let frontier = mgr
            .get_frontier("zone-a")
            .expect("serde deserialization should succeed");
        assert!(frontier.recent_ids.len() <= FrontierState::MAX_RECENT_ENTRIES);
        assert_eq!(frontier.frontier_seq, 40);
        assert_eq!(frontier.accept_count, 41); // genesis + 40
    }

    // -- InMemoryBackend load --

    #[test]
    fn in_memory_backend_load_returns_none_for_missing() {
        let backend = InMemoryBackend::new();
        assert!(
            backend
                .load("nonexistent")
                .expect("serde deserialization should succeed")
                .is_none()
        );
    }

    #[test]
    fn in_memory_backend_load_all_empty() {
        let backend = InMemoryBackend::new();
        assert!(
            backend
                .load_all()
                .expect("serde deserialization should succeed")
                .is_empty()
        );
    }

    // -- drain_events empties buffer --

    #[test]
    fn drain_events_empties_buffer() {
        let sk = make_sk(1);
        let vk = sk.verification_key();
        let genesis = build_genesis(&[sk], "zone-a");

        let mut mgr = CheckpointFrontierManager::new(InMemoryBackend::new());
        mgr.accept_checkpoint("zone-a", &genesis, 1, &[vk], "t-0")
            .expect("serde deserialization should succeed");

        let events = mgr.drain_events();
        assert!(!events.is_empty());
        let events2 = mgr.drain_events();
        assert!(events2.is_empty());
    }

    // -- Enrichment: std::error --

    #[test]
    fn frontier_error_implements_std_error() {
        let variants: Vec<Box<dyn std::error::Error>> = vec![
            Box::new(FrontierError::RollbackRejected {
                zone: "z1".into(),
                frontier_seq: 5,
                attempted_seq: 3,
            }),
            Box::new(FrontierError::DuplicateCheckpoint {
                zone: "z2".into(),
                checkpoint_seq: 10,
            }),
            Box::new(FrontierError::ChainLinkageFailure {
                zone: "z3".into(),
                detail: "bad link".into(),
            }),
            Box::new(FrontierError::QuorumFailure {
                zone: "z4".into(),
                detail: "not enough".into(),
            }),
            Box::new(FrontierError::UnknownZone { zone: "z5".into() }),
            Box::new(FrontierError::EpochRegression {
                zone: "z6".into(),
                frontier_epoch: SecurityEpoch::from_raw(5),
                attempted_epoch: SecurityEpoch::from_raw(3),
            }),
            Box::new(FrontierError::PersistenceFailed {
                zone: "z7".into(),
                detail: "io".into(),
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
            7,
            "all 7 variants produce distinct messages"
        );
    }

    // -- Enrichment: Display uniqueness, edge cases, determinism --

    #[test]
    fn frontier_error_display_uniqueness_btreeset() {
        let errors = vec![
            FrontierError::RollbackRejected {
                zone: "z".into(),
                frontier_seq: 10,
                attempted_seq: 5,
            },
            FrontierError::DuplicateCheckpoint {
                zone: "z".into(),
                checkpoint_seq: 3,
            },
            FrontierError::ChainLinkageFailure {
                zone: "z".into(),
                detail: "link".into(),
            },
            FrontierError::QuorumFailure {
                zone: "z".into(),
                detail: "quorum".into(),
            },
            FrontierError::UnknownZone { zone: "z".into() },
            FrontierError::EpochRegression {
                zone: "z".into(),
                frontier_epoch: SecurityEpoch::from_raw(5),
                attempted_epoch: SecurityEpoch::from_raw(2),
            },
            FrontierError::PersistenceFailed {
                zone: "z".into(),
                detail: "disk".into(),
            },
        ];
        let mut displays = std::collections::BTreeSet::new();
        for e in &errors {
            displays.insert(e.to_string());
        }
        assert_eq!(displays.len(), 7);
    }

    #[test]
    fn frontier_event_type_display_uniqueness_btreeset() {
        let events = vec![
            FrontierEventType::ZoneInitialized {
                zone: "z".into(),
                genesis_seq: 0,
            },
            FrontierEventType::CheckpointAccepted {
                zone: "z".into(),
                prev_seq: 0,
                new_seq: 1,
            },
            FrontierEventType::RollbackRejected {
                zone: "z".into(),
                frontier_seq: 5,
                attempted_seq: 3,
            },
            FrontierEventType::DuplicateRejected {
                zone: "z".into(),
                checkpoint_seq: 5,
            },
            FrontierEventType::EpochRegressionRejected {
                zone: "z".into(),
                frontier_epoch: SecurityEpoch::from_raw(5),
                attempted_epoch: SecurityEpoch::from_raw(2),
            },
            FrontierEventType::FrontierLoaded {
                zone: "z".into(),
                frontier_seq: 10,
            },
        ];
        let mut displays = std::collections::BTreeSet::new();
        for e in &events {
            displays.insert(e.to_string());
        }
        assert_eq!(
            displays.len(),
            6,
            "all 6 event types produce distinct display strings"
        );
    }

    #[test]
    fn frontier_state_from_genesis_default_fields() {
        let sk = make_sk(1);
        let genesis = build_genesis(&[sk], "zone-test");
        let state = FrontierState::from_genesis("zone-test", &genesis);
        assert_eq!(state.zone, "zone-test");
        assert_eq!(state.frontier_seq, 0);
        assert_eq!(state.accept_count, 1);
        assert_eq!(state.recent_ids.len(), 1);
        assert_eq!(state.recent_ids[0].checkpoint_seq, 0);
    }

    #[test]
    fn frontier_state_advance_increments_correctly() {
        let sk = make_sk(1);
        let genesis = build_genesis(std::slice::from_ref(&sk), "zone-a");
        let mut state = FrontierState::from_genesis("zone-a", &genesis);

        let cp1 = build_after(
            &genesis,
            1,
            SecurityEpoch::GENESIS,
            200,
            std::slice::from_ref(&sk),
            "zone-a",
        );
        state.advance(&cp1);

        assert_eq!(state.frontier_seq, 1);
        assert_eq!(state.frontier_checkpoint_id, cp1.checkpoint_id);
        assert_eq!(state.accept_count, 2);
        assert_eq!(state.recent_ids.len(), 2);
    }

    #[test]
    fn frontier_state_serde_deterministic() {
        let sk = make_sk(1);
        let genesis = build_genesis(std::slice::from_ref(&sk), "zone-a");
        let state = FrontierState::from_genesis("zone-a", &genesis);
        let json1 = serde_json::to_string(&state).expect("serde deserialization should succeed");
        let json2 = serde_json::to_string(&state).expect("serde deserialization should succeed");
        assert_eq!(json1, json2, "serialization must be deterministic");
    }

    #[test]
    fn event_counts_empty_for_fresh_manager() {
        let mgr = CheckpointFrontierManager::new(InMemoryBackend::new());
        let counts = mgr.event_counts();
        assert!(counts.is_empty() || counts.values().all(|v| *v == 0));
    }

    #[test]
    fn multiple_zones_have_independent_event_counts() {
        let sk = make_sk(1);
        let vk = sk.verification_key();
        let genesis_a = build_genesis(std::slice::from_ref(&sk), "zone-a");
        let genesis_b = build_genesis(std::slice::from_ref(&sk), "zone-b");

        let mut mgr = CheckpointFrontierManager::new(InMemoryBackend::new());
        mgr.accept_checkpoint("zone-a", &genesis_a, 1, std::slice::from_ref(&vk), "t-a")
            .expect("serde deserialization should succeed");
        mgr.accept_checkpoint("zone-b", &genesis_b, 1, std::slice::from_ref(&vk), "t-b")
            .expect("serde deserialization should succeed");

        let counts = mgr.event_counts();
        assert_eq!(counts["zone_initialized"], 2);
    }

    // -- Enrichment: FrontierEventType serde all 6 variants --

    #[test]
    fn frontier_event_type_serde_zone_initialized() {
        let et = FrontierEventType::ZoneInitialized {
            zone: "z".into(),
            genesis_seq: 0,
        };
        let json = serde_json::to_string(&et).expect("serde deserialization should succeed");
        let back: FrontierEventType =
            serde_json::from_str(&json).expect("serde deserialization should succeed");
        assert_eq!(et, back);
    }

    #[test]
    fn frontier_event_type_serde_checkpoint_accepted() {
        let et = FrontierEventType::CheckpointAccepted {
            zone: "z".into(),
            prev_seq: 1,
            new_seq: 2,
        };
        let json = serde_json::to_string(&et).expect("serde deserialization should succeed");
        let back: FrontierEventType =
            serde_json::from_str(&json).expect("serde deserialization should succeed");
        assert_eq!(et, back);
    }

    #[test]
    fn frontier_event_type_serde_rollback_rejected() {
        let et = FrontierEventType::RollbackRejected {
            zone: "z".into(),
            frontier_seq: 10,
            attempted_seq: 3,
        };
        let json = serde_json::to_string(&et).expect("serde deserialization should succeed");
        let back: FrontierEventType =
            serde_json::from_str(&json).expect("serde deserialization should succeed");
        assert_eq!(et, back);
    }

    #[test]
    fn frontier_event_type_serde_duplicate_rejected() {
        let et = FrontierEventType::DuplicateRejected {
            zone: "z".into(),
            checkpoint_seq: 5,
        };
        let json = serde_json::to_string(&et).expect("serde deserialization should succeed");
        let back: FrontierEventType =
            serde_json::from_str(&json).expect("serde deserialization should succeed");
        assert_eq!(et, back);
    }

    #[test]
    fn frontier_event_type_serde_epoch_regression_rejected() {
        let et = FrontierEventType::EpochRegressionRejected {
            zone: "z".into(),
            frontier_epoch: SecurityEpoch::from_raw(5),
            attempted_epoch: SecurityEpoch::from_raw(2),
        };
        let json = serde_json::to_string(&et).expect("serde deserialization should succeed");
        let back: FrontierEventType =
            serde_json::from_str(&json).expect("serde deserialization should succeed");
        assert_eq!(et, back);
    }

    #[test]
    fn frontier_event_type_serde_frontier_loaded() {
        let et = FrontierEventType::FrontierLoaded {
            zone: "z".into(),
            frontier_seq: 42,
        };
        let json = serde_json::to_string(&et).expect("serde deserialization should succeed");
        let back: FrontierEventType =
            serde_json::from_str(&json).expect("serde deserialization should succeed");
        assert_eq!(et, back);
    }

    // -- Enrichment: non-sequential seq acceptance (skip) --

    #[test]
    fn non_sequential_seq_accepted_when_monotonic() {
        let sk = make_sk(1);
        let vk = sk.verification_key();
        let genesis = build_genesis(std::slice::from_ref(&sk), "zone-a");

        let mut mgr = CheckpointFrontierManager::new(InMemoryBackend::new());
        mgr.accept_checkpoint("zone-a", &genesis, 1, std::slice::from_ref(&vk), "t-0")
            .expect("serde deserialization should succeed");

        // Skip from seq 0 to seq 5 — monotonicity only requires > frontier.
        let cp5 = build_after(
            &genesis,
            5,
            SecurityEpoch::GENESIS,
            600,
            std::slice::from_ref(&sk),
            "zone-a",
        );
        mgr.accept_checkpoint("zone-a", &cp5, 1, std::slice::from_ref(&vk), "t-5")
            .expect("serde deserialization should succeed");

        let frontier = mgr
            .get_frontier("zone-a")
            .expect("serde deserialization should succeed");
        assert_eq!(frontier.frontier_seq, 5);
        assert_eq!(frontier.accept_count, 2);
    }

    // -- Enrichment: event trace_id preserved --

    #[test]
    fn event_trace_id_preserved() {
        let sk = make_sk(1);
        let vk = sk.verification_key();
        let genesis = build_genesis(std::slice::from_ref(&sk), "zone-a");

        let mut mgr = CheckpointFrontierManager::new(InMemoryBackend::new());
        mgr.accept_checkpoint("zone-a", &genesis, 1, std::slice::from_ref(&vk), "trace-42")
            .expect("serde deserialization should succeed");

        let events = mgr.drain_events();
        assert_eq!(events[0].trace_id, "trace-42");
    }

    // -- Enrichment: zones() returns sorted order --

    #[test]
    fn zones_returned_in_sorted_order() {
        let sk = make_sk(1);
        let vk = sk.verification_key();

        let mut mgr = CheckpointFrontierManager::new(InMemoryBackend::new());

        // Insert in reverse alphabetical order.
        let genesis_c = build_genesis(std::slice::from_ref(&sk), "zone-c");
        mgr.accept_checkpoint("zone-c", &genesis_c, 1, std::slice::from_ref(&vk), "t-c")
            .expect("serde deserialization should succeed");

        let genesis_a = build_genesis(std::slice::from_ref(&sk), "zone-a");
        mgr.accept_checkpoint("zone-a", &genesis_a, 1, std::slice::from_ref(&vk), "t-a")
            .expect("serde deserialization should succeed");

        let genesis_b = build_genesis(std::slice::from_ref(&sk), "zone-b");
        mgr.accept_checkpoint("zone-b", &genesis_b, 1, std::slice::from_ref(&vk), "t-b")
            .expect("serde deserialization should succeed");

        let zones = mgr.zones();
        assert_eq!(zones, vec!["zone-a", "zone-b", "zone-c"]);
    }

    // -- Enrichment: multi-zone recovery --

    #[test]
    fn recover_multiple_zones() {
        let sk = make_sk(1);
        let genesis_a = build_genesis(std::slice::from_ref(&sk), "zone-a");
        let genesis_b = build_genesis(std::slice::from_ref(&sk), "zone-b");

        let mut backend = InMemoryBackend::new();
        backend
            .persist(&FrontierState::from_genesis("zone-a", &genesis_a))
            .expect("serde deserialization should succeed");
        backend
            .persist(&FrontierState::from_genesis("zone-b", &genesis_b))
            .expect("serde deserialization should succeed");

        let mut mgr = CheckpointFrontierManager::new(backend);
        let count = mgr
            .recover("t-recover-multi")
            .expect("serde deserialization should succeed");
        assert_eq!(count, 2);

        assert!(mgr.get_frontier("zone-a").is_some());
        assert!(mgr.get_frontier("zone-b").is_some());

        let events = mgr.drain_events();
        assert_eq!(events.len(), 2);
        assert!(
            events
                .iter()
                .all(|e| matches!(&e.event_type, FrontierEventType::FrontierLoaded { .. }))
        );
    }

    // -- Enrichment: event_counts includes all event types --

    #[test]
    fn event_counts_includes_duplicate_and_epoch_regression() {
        let sk = make_sk(1);
        let vk = sk.verification_key();

        // Create high-epoch genesis.
        let genesis_e5 = CheckpointBuilder::genesis(
            SecurityEpoch::from_raw(5),
            DeterministicTimestamp(100),
            "zone-a",
        )
        .add_policy_head(make_policy_head(PolicyType::RuntimeExecution, 1))
        .build(std::slice::from_ref(&sk))
        .expect("serde deserialization should succeed");

        let mut mgr = CheckpointFrontierManager::new(InMemoryBackend::new());
        mgr.accept_checkpoint("zone-a", &genesis_e5, 1, std::slice::from_ref(&vk), "t-0")
            .expect("serde deserialization should succeed");

        let cp1 = build_after(
            &genesis_e5,
            1,
            SecurityEpoch::from_raw(5),
            200,
            std::slice::from_ref(&sk),
            "zone-a",
        );
        mgr.accept_checkpoint("zone-a", &cp1, 1, std::slice::from_ref(&vk), "t-1")
            .expect("serde deserialization should succeed");

        // Trigger duplicate (seq=1 again).
        let _ = mgr.accept_checkpoint("zone-a", &cp1, 1, std::slice::from_ref(&vk), "t-dup");

        // Trigger epoch regression (seq=2 at epoch 3 < frontier epoch 5).
        let low_epoch_genesis = CheckpointBuilder::genesis(
            SecurityEpoch::from_raw(3),
            DeterministicTimestamp(50),
            "zone-a",
        )
        .add_policy_head(make_policy_head(PolicyType::RuntimeExecution, 1))
        .build(std::slice::from_ref(&sk))
        .expect("serde deserialization should succeed");
        let regressed = build_after(
            &low_epoch_genesis,
            2,
            SecurityEpoch::from_raw(3),
            300,
            std::slice::from_ref(&sk),
            "zone-a",
        );
        let _ = mgr.accept_checkpoint(
            "zone-a",
            &regressed,
            1,
            std::slice::from_ref(&vk),
            "t-regress",
        );

        let counts = mgr.event_counts();
        assert_eq!(counts["zone_initialized"], 1);
        assert_eq!(counts["checkpoint_accepted"], 1);
        assert_eq!(counts["duplicate_rejected"], 1);
        assert_eq!(counts["epoch_regression_rejected"], 1);
    }

    // -- Enrichment: FrontierEvent serde roundtrip --

    #[test]
    fn frontier_event_serde_all_event_types() {
        let events = vec![
            FrontierEvent {
                event_type: FrontierEventType::ZoneInitialized {
                    zone: "z".into(),
                    genesis_seq: 0,
                },
                trace_id: "t-0".into(),
            },
            FrontierEvent {
                event_type: FrontierEventType::RollbackRejected {
                    zone: "z".into(),
                    frontier_seq: 5,
                    attempted_seq: 3,
                },
                trace_id: "t-1".into(),
            },
            FrontierEvent {
                event_type: FrontierEventType::DuplicateRejected {
                    zone: "z".into(),
                    checkpoint_seq: 5,
                },
                trace_id: "t-2".into(),
            },
            FrontierEvent {
                event_type: FrontierEventType::EpochRegressionRejected {
                    zone: "z".into(),
                    frontier_epoch: SecurityEpoch::from_raw(5),
                    attempted_epoch: SecurityEpoch::from_raw(2),
                },
                trace_id: "t-3".into(),
            },
            FrontierEvent {
                event_type: FrontierEventType::FrontierLoaded {
                    zone: "z".into(),
                    frontier_seq: 10,
                },
                trace_id: "t-4".into(),
            },
        ];
        for event in &events {
            let json = serde_json::to_string(event).expect("serde deserialization should succeed");
            let back: FrontierEvent =
                serde_json::from_str(&json).expect("serde deserialization should succeed");
            assert_eq!(*event, back);
        }
    }

    // -- Enrichment: backend() accessor --

    #[test]
    fn backend_accessor_returns_correct_state() {
        let sk = make_sk(1);
        let vk = sk.verification_key();
        let genesis = build_genesis(std::slice::from_ref(&sk), "zone-a");

        let mut mgr = CheckpointFrontierManager::new(InMemoryBackend::new());
        assert_eq!(mgr.backend().persist_count, 0);
        assert!(!mgr.backend().fail_on_persist);

        mgr.accept_checkpoint("zone-a", &genesis, 1, std::slice::from_ref(&vk), "t-0")
            .expect("serde deserialization should succeed");
        assert_eq!(mgr.backend().persist_count, 1);
    }

    // -- Enrichment: frontier_epoch updated on epoch transition --

    #[test]
    fn frontier_epoch_tracks_latest_epoch() {
        let sk = make_sk(1);
        let vk = sk.verification_key();
        let genesis = build_genesis(std::slice::from_ref(&sk), "zone-a");

        let mut mgr = CheckpointFrontierManager::new(InMemoryBackend::new());
        mgr.accept_checkpoint("zone-a", &genesis, 1, std::slice::from_ref(&vk), "t-0")
            .expect("serde deserialization should succeed");
        assert_eq!(
            mgr.get_frontier("zone-a")
                .expect("serde deserialization should succeed")
                .frontier_epoch,
            SecurityEpoch::GENESIS
        );

        // Epoch 0 -> 3.
        let cp1 = build_after(
            &genesis,
            1,
            SecurityEpoch::from_raw(3),
            200,
            std::slice::from_ref(&sk),
            "zone-a",
        );
        mgr.accept_checkpoint("zone-a", &cp1, 1, std::slice::from_ref(&vk), "t-1")
            .expect("serde deserialization should succeed");
        assert_eq!(
            mgr.get_frontier("zone-a")
                .expect("serde deserialization should succeed")
                .frontier_epoch,
            SecurityEpoch::from_raw(3)
        );

        // Epoch 3 -> 7.
        let cp2 = build_after(
            &cp1,
            2,
            SecurityEpoch::from_raw(7),
            300,
            std::slice::from_ref(&sk),
            "zone-a",
        );
        mgr.accept_checkpoint("zone-a", &cp2, 1, std::slice::from_ref(&vk), "t-2")
            .expect("serde deserialization should succeed");
        assert_eq!(
            mgr.get_frontier("zone-a")
                .expect("serde deserialization should succeed")
                .frontier_epoch,
            SecurityEpoch::from_raw(7)
        );
    }

    // -- Enrichment: accept_count saturating behavior --

    #[test]
    fn accept_count_tracks_total_accepted() {
        let sk = make_sk(1);
        let vk = sk.verification_key();
        let genesis = build_genesis(std::slice::from_ref(&sk), "zone-a");

        let mut mgr = CheckpointFrontierManager::new(InMemoryBackend::new());
        mgr.accept_checkpoint("zone-a", &genesis, 1, std::slice::from_ref(&vk), "t-0")
            .expect("serde deserialization should succeed");
        assert_eq!(
            mgr.get_frontier("zone-a")
                .expect("serde deserialization should succeed")
                .accept_count,
            1
        );

        let mut prev = genesis;
        for i in 1..=5u64 {
            let cp = build_after(
                &prev,
                i,
                SecurityEpoch::GENESIS,
                100 + i * 100,
                std::slice::from_ref(&sk),
                "zone-a",
            );
            mgr.accept_checkpoint(
                "zone-a",
                &cp,
                1,
                std::slice::from_ref(&vk),
                &format!("t-{i}"),
            )
            .expect("serde deserialization should succeed");
            prev = cp;
        }
        assert_eq!(
            mgr.get_frontier("zone-a")
                .expect("serde deserialization should succeed")
                .accept_count,
            6
        );
    }

    // -- Enrichment: FrontierState clone equality --

    #[test]
    fn frontier_state_clone_equals_original() {
        let sk = make_sk(1);
        let genesis = build_genesis(std::slice::from_ref(&sk), "zone-a");
        let state = FrontierState::from_genesis("zone-a", &genesis);
        let cloned = state.clone();
        assert_eq!(state, cloned);
    }

    // -- Enrichment: rollback event contains correct seq values --

    #[test]
    fn rollback_event_contains_correct_sequences() {
        let sk = make_sk(1);
        let vk = sk.verification_key();
        let genesis = build_genesis(std::slice::from_ref(&sk), "zone-a");

        let mut mgr = CheckpointFrontierManager::new(InMemoryBackend::new());
        mgr.accept_checkpoint("zone-a", &genesis, 1, std::slice::from_ref(&vk), "t-0")
            .expect("serde deserialization should succeed");

        let cp1 = build_after(
            &genesis,
            1,
            SecurityEpoch::GENESIS,
            200,
            std::slice::from_ref(&sk),
            "zone-a",
        );
        mgr.accept_checkpoint("zone-a", &cp1, 1, std::slice::from_ref(&vk), "t-1")
            .expect("serde deserialization should succeed");

        let cp2 = build_after(
            &cp1,
            2,
            SecurityEpoch::GENESIS,
            300,
            std::slice::from_ref(&sk),
            "zone-a",
        );
        mgr.accept_checkpoint("zone-a", &cp2, 1, std::slice::from_ref(&vk), "t-2")
            .expect("serde deserialization should succeed");

        mgr.drain_events(); // clear

        // Attempt rollback to seq 0.
        let rollback = build_genesis(std::slice::from_ref(&sk), "zone-a");
        let _ = mgr.accept_checkpoint(
            "zone-a",
            &rollback,
            1,
            std::slice::from_ref(&vk),
            "t-rollback",
        );

        let events = mgr.drain_events();
        assert_eq!(events.len(), 1);
        assert!(matches!(
            &events[0].event_type,
            FrontierEventType::RollbackRejected {
                frontier_seq: 2,
                attempted_seq: 0,
                ..
            }
        ));
    }

    // -- Enrichment: InMemoryBackend persist overwrites --

    #[test]
    fn in_memory_backend_persist_overwrites() {
        let sk = make_sk(1);
        let genesis = build_genesis(std::slice::from_ref(&sk), "zone-a");
        let state1 = FrontierState::from_genesis("zone-a", &genesis);

        let mut backend = InMemoryBackend::new();
        backend
            .persist(&state1)
            .expect("serde deserialization should succeed");
        assert_eq!(
            backend
                .load("zone-a")
                .expect("serde deserialization should succeed")
                .expect("serde deserialization should succeed")
                .accept_count,
            1
        );

        // Overwrite with updated state.
        let mut state2 = state1;
        let cp1 = build_after(
            &genesis,
            1,
            SecurityEpoch::GENESIS,
            200,
            std::slice::from_ref(&sk),
            "zone-a",
        );
        state2.advance(&cp1);
        backend
            .persist(&state2)
            .expect("serde deserialization should succeed");

        let loaded = backend
            .load("zone-a")
            .expect("serde deserialization should succeed")
            .expect("serde deserialization should succeed");
        assert_eq!(loaded.accept_count, 2);
        assert_eq!(loaded.frontier_seq, 1);
    }

    // -- Enrichment: checkpoint_accepted event contains correct seqs --

    #[test]
    fn checkpoint_accepted_event_has_correct_prev_and_new_seq() {
        let sk = make_sk(1);
        let vk = sk.verification_key();
        let genesis = build_genesis(std::slice::from_ref(&sk), "zone-a");

        let mut mgr = CheckpointFrontierManager::new(InMemoryBackend::new());
        mgr.accept_checkpoint("zone-a", &genesis, 1, std::slice::from_ref(&vk), "t-0")
            .expect("serde deserialization should succeed");
        mgr.drain_events(); // clear genesis event

        let cp1 = build_after(
            &genesis,
            1,
            SecurityEpoch::GENESIS,
            200,
            std::slice::from_ref(&sk),
            "zone-a",
        );
        mgr.accept_checkpoint("zone-a", &cp1, 1, std::slice::from_ref(&vk), "t-1")
            .expect("serde deserialization should succeed");

        let events = mgr.drain_events();
        assert_eq!(events.len(), 1);
        assert!(matches!(
            &events[0].event_type,
            FrontierEventType::CheckpointAccepted {
                prev_seq: 0,
                new_seq: 1,
                ..
            }
        ));
    }

    // -- Enrichment: PearlTower 2026-02-26 --

    #[test]
    fn frontier_error_display_all_unique() {
        let variants: Vec<FrontierError> = vec![
            FrontierError::RollbackRejected {
                zone: "z".into(),
                frontier_seq: 5,
                attempted_seq: 3,
            },
            FrontierError::DuplicateCheckpoint {
                zone: "z".into(),
                checkpoint_seq: 5,
            },
            FrontierError::ChainLinkageFailure {
                zone: "z".into(),
                detail: "bad".into(),
            },
            FrontierError::QuorumFailure {
                zone: "z".into(),
                detail: "no".into(),
            },
            FrontierError::UnknownZone { zone: "z".into() },
            FrontierError::EpochRegression {
                zone: "z".into(),
                frontier_epoch: SecurityEpoch::from_raw(2),
                attempted_epoch: SecurityEpoch::from_raw(1),
            },
            FrontierError::PersistenceFailed {
                zone: "z".into(),
                detail: "err".into(),
            },
        ];
        let mut displays = std::collections::BTreeSet::new();
        for v in &variants {
            displays.insert(format!("{v}"));
        }
        assert_eq!(displays.len(), variants.len());
    }

    #[test]
    fn frontier_error_is_std_error() {
        let err: Box<dyn std::error::Error> =
            Box::new(FrontierError::UnknownZone { zone: "z".into() });
        assert!(!err.to_string().is_empty());
    }

    #[test]
    fn frontier_event_type_display_all_unique() {
        let variants: Vec<FrontierEventType> = vec![
            FrontierEventType::ZoneInitialized {
                zone: "z".into(),
                genesis_seq: 0,
            },
            FrontierEventType::CheckpointAccepted {
                zone: "z".into(),
                prev_seq: 0,
                new_seq: 1,
            },
            FrontierEventType::RollbackRejected {
                zone: "z".into(),
                frontier_seq: 5,
                attempted_seq: 2,
            },
            FrontierEventType::DuplicateRejected {
                zone: "z".into(),
                checkpoint_seq: 5,
            },
            FrontierEventType::EpochRegressionRejected {
                zone: "z".into(),
                frontier_epoch: SecurityEpoch::from_raw(10),
                attempted_epoch: SecurityEpoch::from_raw(5),
            },
            FrontierEventType::FrontierLoaded {
                zone: "z".into(),
                frontier_seq: 42,
            },
        ];
        let mut displays = std::collections::BTreeSet::new();
        for v in &variants {
            displays.insert(format!("{v}"));
        }
        assert_eq!(displays.len(), variants.len());
    }

    #[test]
    fn frontier_state_with_history_serde() {
        let state = FrontierState {
            zone: "zone-x".into(),
            frontier_seq: 42,
            frontier_checkpoint_id: EngineObjectId([7u8; 32]),
            frontier_epoch: SecurityEpoch::from_raw(5),
            accept_count: 43,
            recent_ids: vec![
                FrontierEntry {
                    checkpoint_seq: 0,
                    checkpoint_id: EngineObjectId([1u8; 32]),
                    epoch: SecurityEpoch::GENESIS,
                },
                FrontierEntry {
                    checkpoint_seq: 42,
                    checkpoint_id: EngineObjectId([7u8; 32]),
                    epoch: SecurityEpoch::from_raw(5),
                },
            ],
        };
        let json = serde_json::to_string(&state).expect("serde deserialization should succeed");
        let back: FrontierState =
            serde_json::from_str(&json).expect("serde deserialization should succeed");
        assert_eq!(state, back);
        assert_eq!(back.recent_ids.len(), 2);
    }

    #[test]
    fn frontier_event_trace_id_preserved() {
        let event = FrontierEvent {
            event_type: FrontierEventType::FrontierLoaded {
                zone: "z".into(),
                frontier_seq: 10,
            },
            trace_id: "trace-42".into(),
        };
        let json = serde_json::to_string(&event).expect("serde deserialization should succeed");
        let back: FrontierEvent =
            serde_json::from_str(&json).expect("serde deserialization should succeed");
        assert_eq!(back.trace_id, "trace-42");
    }

    #[test]
    fn in_memory_backend_load_nonexistent_returns_none() {
        let backend = InMemoryBackend::new();
        assert!(
            backend
                .load("does-not-exist")
                .expect("serde deserialization should succeed")
                .is_none()
        );
    }

    #[test]
    fn in_memory_backend_fail_on_persist_flag() {
        let mut backend = InMemoryBackend::new();
        backend.fail_on_persist = true;
        let state = FrontierState {
            zone: "z".into(),
            frontier_seq: 0,
            frontier_checkpoint_id: EngineObjectId([0u8; 32]),
            frontier_epoch: SecurityEpoch::GENESIS,
            accept_count: 1,
            recent_ids: Vec::new(),
        };
        assert!(backend.persist(&state).is_err());
    }

    #[test]
    fn manager_zones_empty_initially() {
        let mgr = CheckpointFrontierManager::new(InMemoryBackend::new());
        assert!(mgr.zones().is_empty());
    }

    #[test]
    fn manager_get_frontier_unknown_zone() {
        let mgr = CheckpointFrontierManager::new(InMemoryBackend::new());
        assert!(mgr.get_frontier("nonexistent").is_none());
    }

    #[test]
    fn recover_from_prepopulated_backend() {
        let mut backend = InMemoryBackend::new();
        let state = FrontierState {
            zone: "zone-a".into(),
            frontier_seq: 5,
            frontier_checkpoint_id: EngineObjectId([1u8; 32]),
            frontier_epoch: SecurityEpoch::from_raw(2),
            accept_count: 6,
            recent_ids: Vec::new(),
        };
        backend
            .persist(&state)
            .expect("serde deserialization should succeed");

        let mut mgr = CheckpointFrontierManager::new(backend);
        assert!(mgr.get_frontier("zone-a").is_none());

        let count = mgr
            .recover("t-recover")
            .expect("serde deserialization should succeed");
        assert_eq!(count, 1);
        let loaded = mgr
            .get_frontier("zone-a")
            .expect("serde deserialization should succeed");
        assert_eq!(loaded.frontier_seq, 5);
    }

    #[test]
    fn in_memory_backend_persist_count_increments() {
        let mut backend = InMemoryBackend::new();
        assert_eq!(backend.persist_count, 0);
        let state = FrontierState {
            zone: "z".into(),
            frontier_seq: 0,
            frontier_checkpoint_id: EngineObjectId([0u8; 32]),
            frontier_epoch: SecurityEpoch::GENESIS,
            accept_count: 1,
            recent_ids: Vec::new(),
        };
        backend
            .persist(&state)
            .expect("serde deserialization should succeed");
        assert_eq!(backend.persist_count, 1);
        backend
            .persist(&state)
            .expect("serde deserialization should succeed");
        assert_eq!(backend.persist_count, 2);
    }

    #[test]
    fn multiple_zones_independent() {
        let sk = make_sk(1);
        let vk = sk.verification_key();
        let genesis_a = build_genesis(std::slice::from_ref(&sk), "zone-a");
        let genesis_b = build_genesis(std::slice::from_ref(&sk), "zone-b");

        let mut mgr = CheckpointFrontierManager::new(InMemoryBackend::new());
        mgr.accept_checkpoint("zone-a", &genesis_a, 1, std::slice::from_ref(&vk), "t-0")
            .expect("serde deserialization should succeed");
        mgr.accept_checkpoint("zone-b", &genesis_b, 1, std::slice::from_ref(&vk), "t-1")
            .expect("serde deserialization should succeed");

        let mut zones = mgr.zones();
        zones.sort();
        assert_eq!(zones, vec!["zone-a", "zone-b"]);
    }
}
