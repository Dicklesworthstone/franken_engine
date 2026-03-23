//! Lease-backed remote liveness tracking with explicit timeout and
//! escalation paths.
//!
//! Every remote endpoint relationship is governed by a lease providing
//! bounded liveness guarantees. When liveness is lost (lease expires
//! without renewal), deterministic escalation occurs.
//!
//! Lease types:
//! - `RemoteEndpointLease`: marks endpoint as unreachable, suspends ops.
//! - `OperationLease`: cancels the associated operation.
//! - `SessionLease`: terminates the session and cleans up.
//!
//! Epoch binding: leases granted in epoch N are invalidated on epoch N+1
//! transition unless explicitly re-granted.
//!
//! Plan references: Section 10.11 item 23, 9G.7 (remote-effects contract),
//! Top-10 #5 (supply-chain trust), #10 (provenance + revocation fabric).

use std::collections::BTreeMap;
use std::fmt;

use serde::{Deserialize, Serialize};

use crate::security_epoch::SecurityEpoch;

// ---------------------------------------------------------------------------
// LeaseId — unique identifier
// ---------------------------------------------------------------------------

/// Unique identifier for a lease.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct LeaseId(pub u64);

impl LeaseId {
    /// Create from a raw value.
    pub fn from_raw(id: u64) -> Self {
        Self(id)
    }

    /// Access the raw value.
    pub fn as_u64(&self) -> u64 {
        self.0
    }
}

impl fmt::Display for LeaseId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "lease:{}", self.0)
    }
}

// ---------------------------------------------------------------------------
// LeaseType — classification of leases
// ---------------------------------------------------------------------------

/// Classification of lease purpose, determining escalation behavior.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum LeaseType {
    /// Remote endpoint liveness. Expiration marks endpoint unreachable.
    RemoteEndpoint,
    /// Single operation liveness. Expiration cancels the operation.
    Operation,
    /// Session liveness. Expiration terminates the session.
    Session,
}

impl fmt::Display for LeaseType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::RemoteEndpoint => f.write_str("remote_endpoint"),
            Self::Operation => f.write_str("operation"),
            Self::Session => f.write_str("session"),
        }
    }
}

// ---------------------------------------------------------------------------
// LeaseStatus — current state of a lease
// ---------------------------------------------------------------------------

/// Current status of a lease.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum LeaseStatus {
    /// Lease is active and has not expired.
    Active,
    /// Lease has expired without renewal.
    Expired,
    /// Lease was explicitly released before expiration.
    Released,
}

impl fmt::Display for LeaseStatus {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Active => f.write_str("active"),
            Self::Expired => f.write_str("expired"),
            Self::Released => f.write_str("released"),
        }
    }
}

// ---------------------------------------------------------------------------
// EscalationAction — what happens when a lease expires
// ---------------------------------------------------------------------------

/// Action taken when a lease expires.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum EscalationAction {
    /// Mark remote endpoint as unreachable, suspend pending operations.
    MarkEndpointUnreachable { holder: String },
    /// Cancel the associated operation via region-quiescence.
    CancelOperation { holder: String },
    /// Terminate the session and clean up resources.
    TerminateSession { holder: String },
}

impl fmt::Display for EscalationAction {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::MarkEndpointUnreachable { holder } => {
                write!(f, "mark_endpoint_unreachable({holder})")
            }
            Self::CancelOperation { holder } => {
                write!(f, "cancel_operation({holder})")
            }
            Self::TerminateSession { holder } => {
                write!(f, "terminate_session({holder})")
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Lease — the core lease type
// ---------------------------------------------------------------------------

/// A lease providing bounded liveness guarantees for a remote relationship.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Lease {
    /// Unique lease identifier.
    pub lease_id: LeaseId,
    /// Identity of the lease holder (service, endpoint, session).
    pub holder: String,
    /// Type of lease (determines escalation on expiry).
    pub lease_type: LeaseType,
    /// Virtual tick at which the lease was granted.
    pub granted_at: u64,
    /// Virtual tick at which the lease expires.
    pub expires_at: u64,
    /// Configured time-to-live in ticks.
    pub ttl: u64,
    /// Epoch in which the lease was granted.
    pub epoch: SecurityEpoch,
    /// Number of times the lease has been renewed.
    pub renewal_count: u32,
    /// Current status.
    pub status: LeaseStatus,
}

impl Lease {
    /// Check if the lease is active at the given tick.
    pub fn is_active_at(&self, current_ticks: u64) -> bool {
        self.status == LeaseStatus::Active && current_ticks < self.expires_at
    }

    /// The tick at which renewal should be proactively attempted (ttl/3).
    pub fn renewal_due_at(&self) -> u64 {
        let renewal_interval = self.ttl / 3;
        self.expires_at.saturating_sub(self.ttl) + renewal_interval
    }

    /// Determine the escalation action for this lease type.
    pub fn escalation_action(&self) -> EscalationAction {
        match self.lease_type {
            LeaseType::RemoteEndpoint => EscalationAction::MarkEndpointUnreachable {
                holder: self.holder.clone(),
            },
            LeaseType::Operation => EscalationAction::CancelOperation {
                holder: self.holder.clone(),
            },
            LeaseType::Session => EscalationAction::TerminateSession {
                holder: self.holder.clone(),
            },
        }
    }
}

// ---------------------------------------------------------------------------
// LeaseEvent — structured audit event
// ---------------------------------------------------------------------------

/// Structured event emitted for lease lifecycle changes.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LeaseEvent {
    /// Lease identifier.
    pub lease_id: u64,
    /// Lease holder.
    pub holder: String,
    /// Epoch at time of event.
    pub epoch_id: u64,
    /// TTL in ticks.
    pub ttl: u64,
    /// Current status.
    pub status: String,
    /// Escalation action taken (if any).
    pub escalation_action: String,
    /// Trace identifier.
    pub trace_id: String,
    /// Event type.
    pub event: String,
    /// Renewal count at time of event.
    pub renewal_count: u32,
}

// ---------------------------------------------------------------------------
// LeaseError — typed errors
// ---------------------------------------------------------------------------

/// Errors from lease operations.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum LeaseError {
    /// Lease not found.
    LeaseNotFound { lease_id: u64 },
    /// Attempted to renew an expired lease.
    LeaseExpired { lease_id: u64, expired_at: u64 },
    /// Attempted to renew a released lease.
    LeaseReleased { lease_id: u64 },
    /// Lease was granted in a different epoch.
    EpochMismatch {
        lease_id: u64,
        lease_epoch: SecurityEpoch,
        current_epoch: SecurityEpoch,
    },
    /// TTL is zero.
    ZeroTtl,
    /// Holder name is empty.
    EmptyHolder,
}

impl fmt::Display for LeaseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::LeaseNotFound { lease_id } => {
                write!(f, "lease {lease_id} not found")
            }
            Self::LeaseExpired {
                lease_id,
                expired_at,
            } => {
                write!(f, "lease {lease_id} expired at tick {expired_at}")
            }
            Self::LeaseReleased { lease_id } => {
                write!(f, "lease {lease_id} already released")
            }
            Self::EpochMismatch {
                lease_id,
                lease_epoch,
                current_epoch,
            } => {
                write!(
                    f,
                    "lease {lease_id} epoch mismatch: lease at {lease_epoch}, current {current_epoch}"
                )
            }
            Self::ZeroTtl => f.write_str("TTL must be non-zero"),
            Self::EmptyHolder => f.write_str("holder must be non-empty"),
        }
    }
}

impl std::error::Error for LeaseError {}

// ---------------------------------------------------------------------------
// LeaseStore — the lease registry
// ---------------------------------------------------------------------------

/// Store of active leases with expiration tracking.
///
/// Uses `BTreeMap` for deterministic ordering. Leases are sorted by ID
/// for lookup and by expiration time for efficient next-expiry checking.
#[derive(Debug)]
pub struct LeaseStore {
    /// Current security epoch.
    current_epoch: SecurityEpoch,
    /// Next lease ID to assign.
    next_id: u64,
    /// Active leases by ID.
    leases: BTreeMap<u64, Lease>,
    /// Expiration index: expires_at -> lease IDs (for efficient scanning).
    expiration_index: BTreeMap<u64, Vec<u64>>,
    /// Accumulated audit events.
    events: Vec<LeaseEvent>,
    /// Counters by event type.
    event_counts: BTreeMap<String, u64>,
}

impl LeaseStore {
    /// Create a new lease store.
    pub fn new(epoch: SecurityEpoch) -> Self {
        Self {
            current_epoch: epoch,
            next_id: 1,
            leases: BTreeMap::new(),
            expiration_index: BTreeMap::new(),
            events: Vec::new(),
            event_counts: BTreeMap::new(),
        }
    }

    /// Current epoch.
    pub fn epoch(&self) -> SecurityEpoch {
        self.current_epoch
    }

    /// Grant a new lease.
    pub fn grant(
        &mut self,
        holder: &str,
        lease_type: LeaseType,
        ttl: u64,
        current_ticks: u64,
        trace_id: &str,
    ) -> Result<LeaseId, LeaseError> {
        if ttl == 0 {
            return Err(LeaseError::ZeroTtl);
        }
        if holder.is_empty() {
            return Err(LeaseError::EmptyHolder);
        }

        let lease_id = LeaseId::from_raw(self.next_id);
        self.next_id += 1;

        let lease = Lease {
            lease_id: lease_id.clone(),
            holder: holder.to_string(),
            lease_type,
            granted_at: current_ticks,
            expires_at: current_ticks.saturating_add(ttl),
            ttl,
            epoch: self.current_epoch,
            renewal_count: 0,
            status: LeaseStatus::Active,
        };

        self.expiration_index
            .entry(lease.expires_at)
            .or_default()
            .push(lease_id.as_u64());

        self.emit_event(LeaseEvent {
            lease_id: lease_id.as_u64(),
            holder: holder.to_string(),
            epoch_id: self.current_epoch.as_u64(),
            ttl,
            status: "active".to_string(),
            escalation_action: String::new(),
            trace_id: trace_id.to_string(),
            event: "grant".to_string(),
            renewal_count: 0,
        });

        self.leases.insert(lease_id.as_u64(), lease);
        self.record_count("grant");

        Ok(lease_id)
    }

    /// Renew an existing lease, extending it by its TTL.
    pub fn renew(
        &mut self,
        lease_id: &LeaseId,
        current_ticks: u64,
        trace_id: &str,
    ) -> Result<(), LeaseError> {
        let lease = self
            .leases
            .get_mut(&lease_id.as_u64())
            .ok_or(LeaseError::LeaseNotFound {
                lease_id: lease_id.as_u64(),
            })?;

        match lease.status {
            LeaseStatus::Released => {
                return Err(LeaseError::LeaseReleased {
                    lease_id: lease_id.as_u64(),
                });
            }
            LeaseStatus::Expired => {
                return Err(LeaseError::LeaseExpired {
                    lease_id: lease_id.as_u64(),
                    expired_at: lease.expires_at,
                });
            }
            LeaseStatus::Active => {}
        }

        // Check if actually expired by time.
        if current_ticks >= lease.expires_at {
            lease.status = LeaseStatus::Expired;
            return Err(LeaseError::LeaseExpired {
                lease_id: lease_id.as_u64(),
                expired_at: lease.expires_at,
            });
        }

        // Epoch check.
        if lease.epoch != self.current_epoch {
            return Err(LeaseError::EpochMismatch {
                lease_id: lease_id.as_u64(),
                lease_epoch: lease.epoch,
                current_epoch: self.current_epoch,
            });
        }

        // Remove from old expiration index.
        if let Some(ids) = self.expiration_index.get_mut(&lease.expires_at) {
            ids.retain(|id| *id != lease_id.as_u64());
            if ids.is_empty() {
                self.expiration_index.remove(&lease.expires_at);
            }
        }

        // Extend.
        lease.expires_at = current_ticks.saturating_add(lease.ttl);
        lease.renewal_count = lease.renewal_count.saturating_add(1);

        // Extract event data before dropping mutable lease borrow.
        let holder = lease.holder.clone();
        let ttl = lease.ttl;
        let renewal_count = lease.renewal_count;
        let new_expires_at = lease.expires_at;

        // Add to new expiration index.
        self.expiration_index
            .entry(new_expires_at)
            .or_default()
            .push(lease_id.as_u64());

        self.emit_event(LeaseEvent {
            lease_id: lease_id.as_u64(),
            holder,
            epoch_id: self.current_epoch.as_u64(),
            ttl,
            status: "active".to_string(),
            escalation_action: String::new(),
            trace_id: trace_id.to_string(),
            event: "renew".to_string(),
            renewal_count,
        });
        self.record_count("renew");

        Ok(())
    }

    /// Explicitly release a lease before expiration.
    pub fn release(&mut self, lease_id: &LeaseId, trace_id: &str) -> Result<(), LeaseError> {
        let lease = self
            .leases
            .get_mut(&lease_id.as_u64())
            .ok_or(LeaseError::LeaseNotFound {
                lease_id: lease_id.as_u64(),
            })?;

        if lease.status == LeaseStatus::Released {
            return Err(LeaseError::LeaseReleased {
                lease_id: lease_id.as_u64(),
            });
        }

        // Remove from expiration index.
        if let Some(ids) = self.expiration_index.get_mut(&lease.expires_at) {
            ids.retain(|id| *id != lease_id.as_u64());
            if ids.is_empty() {
                self.expiration_index.remove(&lease.expires_at);
            }
        }

        lease.status = LeaseStatus::Released;

        // Extract event data before dropping mutable lease borrow.
        let holder = lease.holder.clone();
        let ttl = lease.ttl;
        let renewal_count = lease.renewal_count;

        self.emit_event(LeaseEvent {
            lease_id: lease_id.as_u64(),
            holder,
            epoch_id: self.current_epoch.as_u64(),
            ttl,
            status: "released".to_string(),
            escalation_action: String::new(),
            trace_id: trace_id.to_string(),
            event: "release".to_string(),
            renewal_count,
        });
        self.record_count("release");

        Ok(())
    }

    /// Check the status of a lease at the given tick.
    pub fn check(
        &mut self,
        lease_id: &LeaseId,
        current_ticks: u64,
    ) -> Result<LeaseStatus, LeaseError> {
        let lease = self
            .leases
            .get_mut(&lease_id.as_u64())
            .ok_or(LeaseError::LeaseNotFound {
                lease_id: lease_id.as_u64(),
            })?;

        // Transition active -> expired if time has passed.
        if lease.status == LeaseStatus::Active && current_ticks >= lease.expires_at {
            lease.status = LeaseStatus::Expired;
        }

        Ok(lease.status)
    }

    /// Look up a lease by ID.
    pub fn get(&self, lease_id: &LeaseId) -> Option<&Lease> {
        self.leases.get(&lease_id.as_u64())
    }

    /// Scan for expired leases and trigger escalation.
    ///
    /// Returns the list of escalation actions that should be taken.
    pub fn scan_expired(&mut self, current_ticks: u64, trace_id: &str) -> Vec<EscalationAction> {
        let mut actions = Vec::new();

        // Find all leases that have expired.
        let expired_keys: Vec<u64> = self
            .expiration_index
            .range(..=current_ticks)
            .flat_map(|(_, ids)| ids.iter().copied())
            .collect();

        let mut pending_events: Vec<(LeaseEvent, EscalationAction)> = Vec::new();
        for lease_id in expired_keys {
            if let Some(lease) = self.leases.get_mut(&lease_id)
                && lease.status == LeaseStatus::Active
            {
                lease.status = LeaseStatus::Expired;
                let action = lease.escalation_action();
                let holder = lease.holder.clone();
                let ttl = lease.ttl;
                let renewal_count = lease.renewal_count;

                pending_events.push((
                    LeaseEvent {
                        lease_id,
                        holder,
                        epoch_id: self.current_epoch.as_u64(),
                        ttl,
                        status: "expired".to_string(),
                        escalation_action: action.to_string(),
                        trace_id: trace_id.to_string(),
                        event: "expiration".to_string(),
                        renewal_count,
                    },
                    action,
                ));
            }
        }
        for (event, action) in pending_events {
            self.emit_event(event);
            self.record_count("expiration");
            actions.push(action);
        }

        // Clean up expiration index.
        let to_remove: Vec<u64> = self
            .expiration_index
            .range(..=current_ticks)
            .map(|(k, _)| *k)
            .collect();
        for k in to_remove {
            self.expiration_index.remove(&k);
        }

        actions
    }

    /// Advance to a new epoch, invalidating leases from old epochs.
    ///
    /// Returns escalation actions for all invalidated leases.
    pub fn advance_epoch(
        &mut self,
        new_epoch: SecurityEpoch,
        trace_id: &str,
    ) -> Vec<EscalationAction> {
        let mut actions = Vec::new();
        let mut pending_events: Vec<(LeaseEvent, EscalationAction)> = Vec::new();

        for lease in self.leases.values_mut() {
            if lease.status == LeaseStatus::Active && lease.epoch != new_epoch {
                lease.status = LeaseStatus::Expired;
                let action = lease.escalation_action();
                let lid = lease.lease_id.as_u64();
                let holder = lease.holder.clone();
                let ttl = lease.ttl;
                let renewal_count = lease.renewal_count;

                pending_events.push((
                    LeaseEvent {
                        lease_id: lid,
                        holder,
                        epoch_id: new_epoch.as_u64(),
                        ttl,
                        status: "expired".to_string(),
                        escalation_action: action.to_string(),
                        trace_id: trace_id.to_string(),
                        event: "epoch_invalidation".to_string(),
                        renewal_count,
                    },
                    action,
                ));
            }
        }
        for (event, action) in pending_events {
            self.emit_event(event);
            self.record_count("epoch_invalidation");
            actions.push(action);
        }

        self.current_epoch = new_epoch;
        // Rebuild expiration index (only active leases).
        self.expiration_index.clear();
        for (id, lease) in &self.leases {
            if lease.status == LeaseStatus::Active {
                self.expiration_index
                    .entry(lease.expires_at)
                    .or_default()
                    .push(*id);
            }
        }

        actions
    }

    /// Find leases that need renewal (due at or before current_ticks).
    pub fn leases_due_for_renewal(&self, current_ticks: u64) -> Vec<LeaseId> {
        self.leases
            .values()
            .filter(|l| l.status == LeaseStatus::Active && l.renewal_due_at() <= current_ticks)
            .map(|l| l.lease_id.clone())
            .collect()
    }

    /// Number of active leases.
    pub fn active_count(&self) -> usize {
        self.leases
            .values()
            .filter(|l| l.status == LeaseStatus::Active)
            .count()
    }

    /// Total number of tracked leases (all statuses).
    pub fn total_count(&self) -> usize {
        self.leases.len()
    }

    /// Drain accumulated audit events.
    pub fn drain_events(&mut self) -> Vec<LeaseEvent> {
        std::mem::take(&mut self.events)
    }

    /// Per-event-type counters.
    pub fn event_counts(&self) -> &BTreeMap<String, u64> {
        &self.event_counts
    }

    // -- Internal --

    fn emit_event(&mut self, event: LeaseEvent) {
        self.events.push(event);
    }

    fn record_count(&mut self, event_type: &str) {
        *self.event_counts.entry(event_type.to_string()).or_insert(0) += 1;
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn test_epoch() -> SecurityEpoch {
        SecurityEpoch::from_raw(1)
    }

    // -- LeaseId --

    #[test]
    fn lease_id_display() {
        assert_eq!(LeaseId::from_raw(42).to_string(), "lease:42");
    }

    // -- LeaseType --

    #[test]
    fn lease_type_display() {
        assert_eq!(LeaseType::RemoteEndpoint.to_string(), "remote_endpoint");
        assert_eq!(LeaseType::Operation.to_string(), "operation");
        assert_eq!(LeaseType::Session.to_string(), "session");
    }

    // -- LeaseStatus --

    #[test]
    fn lease_status_display() {
        assert_eq!(LeaseStatus::Active.to_string(), "active");
        assert_eq!(LeaseStatus::Expired.to_string(), "expired");
        assert_eq!(LeaseStatus::Released.to_string(), "released");
    }

    // -- Lease grant --

    #[test]
    fn grant_lease() {
        let mut store = LeaseStore::new(test_epoch());
        let id = store
            .grant("node-1", LeaseType::RemoteEndpoint, 100, 0, "trace-1")
            .unwrap();
        assert_eq!(id.as_u64(), 1);
        assert_eq!(store.active_count(), 1);

        let lease = store.get(&id).unwrap();
        assert_eq!(lease.holder, "node-1");
        assert_eq!(lease.lease_type, LeaseType::RemoteEndpoint);
        assert_eq!(lease.ttl, 100);
        assert_eq!(lease.expires_at, 100);
        assert_eq!(lease.renewal_count, 0);
        assert_eq!(lease.status, LeaseStatus::Active);
    }

    #[test]
    fn grant_multiple_leases() {
        let mut store = LeaseStore::new(test_epoch());
        let id1 = store
            .grant("node-1", LeaseType::RemoteEndpoint, 100, 0, "t1")
            .unwrap();
        let id2 = store
            .grant("node-2", LeaseType::Operation, 200, 10, "t2")
            .unwrap();
        let id3 = store
            .grant("session-1", LeaseType::Session, 50, 20, "t3")
            .unwrap();
        assert_eq!(store.active_count(), 3);
        assert_eq!(store.total_count(), 3);
        assert_ne!(id1, id2);
        assert_ne!(id2, id3);
    }

    #[test]
    fn grant_rejects_zero_ttl() {
        let mut store = LeaseStore::new(test_epoch());
        assert!(matches!(
            store.grant("node-1", LeaseType::RemoteEndpoint, 0, 0, "t"),
            Err(LeaseError::ZeroTtl)
        ));
    }

    #[test]
    fn grant_rejects_empty_holder() {
        let mut store = LeaseStore::new(test_epoch());
        assert!(matches!(
            store.grant("", LeaseType::RemoteEndpoint, 100, 0, "t"),
            Err(LeaseError::EmptyHolder)
        ));
    }

    // -- Lease check --

    #[test]
    fn check_active_lease() {
        let mut store = LeaseStore::new(test_epoch());
        let id = store
            .grant("node-1", LeaseType::RemoteEndpoint, 100, 0, "t")
            .unwrap();
        assert_eq!(store.check(&id, 50).unwrap(), LeaseStatus::Active);
    }

    #[test]
    fn check_expired_lease() {
        let mut store = LeaseStore::new(test_epoch());
        let id = store
            .grant("node-1", LeaseType::RemoteEndpoint, 100, 0, "t")
            .unwrap();
        assert_eq!(store.check(&id, 100).unwrap(), LeaseStatus::Expired);
    }

    #[test]
    fn check_released_lease() {
        let mut store = LeaseStore::new(test_epoch());
        let id = store
            .grant("node-1", LeaseType::RemoteEndpoint, 100, 0, "t")
            .unwrap();
        store.release(&id, "t").unwrap();
        assert_eq!(store.check(&id, 50).unwrap(), LeaseStatus::Released);
    }

    #[test]
    fn check_unknown_lease() {
        let mut store = LeaseStore::new(test_epoch());
        assert!(matches!(
            store.check(&LeaseId::from_raw(999), 0),
            Err(LeaseError::LeaseNotFound { .. })
        ));
    }

    // -- Lease renewal --

    #[test]
    fn renew_extends_expiration() {
        let mut store = LeaseStore::new(test_epoch());
        let id = store
            .grant("node-1", LeaseType::RemoteEndpoint, 100, 0, "t")
            .unwrap();

        store.renew(&id, 50, "t-renew").unwrap();
        let lease = store.get(&id).unwrap();
        assert_eq!(lease.expires_at, 150); // 50 + 100
        assert_eq!(lease.renewal_count, 1);
    }

    #[test]
    fn renew_multiple_times() {
        let mut store = LeaseStore::new(test_epoch());
        let id = store
            .grant("node-1", LeaseType::RemoteEndpoint, 100, 0, "t")
            .unwrap();

        store.renew(&id, 30, "t1").unwrap();
        store.renew(&id, 60, "t2").unwrap();
        let lease = store.get(&id).unwrap();
        assert_eq!(lease.expires_at, 160); // 60 + 100
        assert_eq!(lease.renewal_count, 2);
    }

    #[test]
    fn renew_expired_fails() {
        let mut store = LeaseStore::new(test_epoch());
        let id = store
            .grant("node-1", LeaseType::RemoteEndpoint, 100, 0, "t")
            .unwrap();

        let err = store.renew(&id, 200, "t-renew").unwrap_err();
        assert!(matches!(err, LeaseError::LeaseExpired { .. }));
    }

    #[test]
    fn renew_released_fails() {
        let mut store = LeaseStore::new(test_epoch());
        let id = store
            .grant("node-1", LeaseType::RemoteEndpoint, 100, 0, "t")
            .unwrap();
        store.release(&id, "t-rel").unwrap();

        let err = store.renew(&id, 50, "t-renew").unwrap_err();
        assert!(matches!(err, LeaseError::LeaseReleased { .. }));
    }

    #[test]
    fn renew_unknown_fails() {
        let mut store = LeaseStore::new(test_epoch());
        assert!(matches!(
            store.renew(&LeaseId::from_raw(999), 0, "t"),
            Err(LeaseError::LeaseNotFound { .. })
        ));
    }

    // -- Lease release --

    #[test]
    fn release_lease() {
        let mut store = LeaseStore::new(test_epoch());
        let id = store
            .grant("node-1", LeaseType::RemoteEndpoint, 100, 0, "t")
            .unwrap();
        store.release(&id, "t-rel").unwrap();
        assert_eq!(store.active_count(), 0);

        let lease = store.get(&id).unwrap();
        assert_eq!(lease.status, LeaseStatus::Released);
    }

    #[test]
    fn double_release_fails() {
        let mut store = LeaseStore::new(test_epoch());
        let id = store
            .grant("node-1", LeaseType::RemoteEndpoint, 100, 0, "t")
            .unwrap();
        store.release(&id, "t1").unwrap();
        assert!(matches!(
            store.release(&id, "t2"),
            Err(LeaseError::LeaseReleased { .. })
        ));
    }

    // -- Expiration scanning --

    #[test]
    fn scan_detects_expired_leases() {
        let mut store = LeaseStore::new(test_epoch());
        store
            .grant("node-1", LeaseType::RemoteEndpoint, 100, 0, "t1")
            .unwrap();
        store
            .grant("op-1", LeaseType::Operation, 50, 10, "t2")
            .unwrap();

        // At tick 70, only op-1 (expires at 60) should be expired.
        let actions = store.scan_expired(70, "trace-scan");
        assert_eq!(actions.len(), 1);
        assert!(matches!(
            &actions[0],
            EscalationAction::CancelOperation { holder } if holder == "op-1"
        ));
    }

    #[test]
    fn scan_detects_multiple_expirations() {
        let mut store = LeaseStore::new(test_epoch());
        store
            .grant("node-1", LeaseType::RemoteEndpoint, 100, 0, "t1")
            .unwrap();
        store
            .grant("session-1", LeaseType::Session, 50, 0, "t2")
            .unwrap();

        // At tick 200, both should be expired.
        let actions = store.scan_expired(200, "trace-scan");
        assert_eq!(actions.len(), 2);
    }

    #[test]
    fn scan_skips_already_expired() {
        let mut store = LeaseStore::new(test_epoch());
        store
            .grant("node-1", LeaseType::RemoteEndpoint, 100, 0, "t")
            .unwrap();

        let a1 = store.scan_expired(200, "t1");
        assert_eq!(a1.len(), 1);

        // Second scan should not re-escalate.
        let a2 = store.scan_expired(300, "t2");
        assert!(a2.is_empty());
    }

    // -- Epoch binding --

    #[test]
    fn epoch_advance_invalidates_old_leases() {
        let mut store = LeaseStore::new(test_epoch());
        store
            .grant("node-1", LeaseType::RemoteEndpoint, 1000, 0, "t")
            .unwrap();
        assert_eq!(store.active_count(), 1);

        let actions = store.advance_epoch(SecurityEpoch::from_raw(2), "trace-epoch");
        assert_eq!(actions.len(), 1);
        assert!(matches!(
            &actions[0],
            EscalationAction::MarkEndpointUnreachable { holder } if holder == "node-1"
        ));
        assert_eq!(store.active_count(), 0);
    }

    #[test]
    fn renew_after_epoch_advance_fails() {
        let mut store = LeaseStore::new(test_epoch());
        let id = store
            .grant("node-1", LeaseType::RemoteEndpoint, 1000, 0, "t")
            .unwrap();

        store.advance_epoch(SecurityEpoch::from_raw(2), "t-epoch");
        let err = store.renew(&id, 50, "t-renew").unwrap_err();
        assert!(matches!(err, LeaseError::LeaseExpired { .. }));
    }

    // -- Renewal due --

    #[test]
    fn renewal_due_at_calculation() {
        let mut store = LeaseStore::new(test_epoch());
        let id = store
            .grant("node-1", LeaseType::RemoteEndpoint, 300, 100, "t")
            .unwrap();
        let lease = store.get(&id).unwrap();
        // ttl=300, granted_at=100, expires_at=400
        // renewal_due_at = expires_at - ttl + ttl/3 = 400 - 300 + 100 = 200
        assert_eq!(lease.renewal_due_at(), 200);
    }

    #[test]
    fn leases_due_for_renewal() {
        let mut store = LeaseStore::new(test_epoch());
        let id1 = store
            .grant("node-1", LeaseType::RemoteEndpoint, 300, 0, "t1")
            .unwrap();
        let _id2 = store
            .grant("node-2", LeaseType::RemoteEndpoint, 900, 0, "t2")
            .unwrap();

        // id1: renewal_due_at = 0 + 100 = 100
        // id2: renewal_due_at = 0 + 300 = 300
        let due = store.leases_due_for_renewal(150);
        assert_eq!(due.len(), 1);
        assert_eq!(due[0], id1);
    }

    // -- Escalation actions --

    #[test]
    fn escalation_action_for_endpoint() {
        let mut store = LeaseStore::new(test_epoch());
        let id = store
            .grant("node-1", LeaseType::RemoteEndpoint, 10, 0, "t")
            .unwrap();
        let lease = store.get(&id).unwrap();
        assert!(matches!(
            lease.escalation_action(),
            EscalationAction::MarkEndpointUnreachable { .. }
        ));
    }

    #[test]
    fn escalation_action_for_operation() {
        let mut store = LeaseStore::new(test_epoch());
        let id = store
            .grant("op-1", LeaseType::Operation, 10, 0, "t")
            .unwrap();
        let lease = store.get(&id).unwrap();
        assert!(matches!(
            lease.escalation_action(),
            EscalationAction::CancelOperation { .. }
        ));
    }

    #[test]
    fn escalation_action_for_session() {
        let mut store = LeaseStore::new(test_epoch());
        let id = store
            .grant("sess-1", LeaseType::Session, 10, 0, "t")
            .unwrap();
        let lease = store.get(&id).unwrap();
        assert!(matches!(
            lease.escalation_action(),
            EscalationAction::TerminateSession { .. }
        ));
    }

    // -- Audit events --

    #[test]
    fn grant_emits_event() {
        let mut store = LeaseStore::new(test_epoch());
        store
            .grant("node-1", LeaseType::RemoteEndpoint, 100, 0, "trace-g")
            .unwrap();

        let events = store.drain_events();
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].event, "grant");
        assert_eq!(events[0].holder, "node-1");
        assert_eq!(events[0].trace_id, "trace-g");
    }

    #[test]
    fn renew_emits_event() {
        let mut store = LeaseStore::new(test_epoch());
        let id = store
            .grant("node-1", LeaseType::RemoteEndpoint, 100, 0, "t")
            .unwrap();
        store.drain_events();
        store.renew(&id, 50, "trace-r").unwrap();

        let events = store.drain_events();
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].event, "renew");
        assert_eq!(events[0].renewal_count, 1);
    }

    #[test]
    fn release_emits_event() {
        let mut store = LeaseStore::new(test_epoch());
        let id = store
            .grant("node-1", LeaseType::RemoteEndpoint, 100, 0, "t")
            .unwrap();
        store.drain_events();
        store.release(&id, "trace-rel").unwrap();

        let events = store.drain_events();
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].event, "release");
        assert_eq!(events[0].status, "released");
    }

    #[test]
    fn expiration_emits_event_with_escalation() {
        let mut store = LeaseStore::new(test_epoch());
        store
            .grant("node-1", LeaseType::RemoteEndpoint, 100, 0, "t")
            .unwrap();
        store.drain_events();
        store.scan_expired(200, "trace-exp");

        let events = store.drain_events();
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].event, "expiration");
        assert!(
            events[0]
                .escalation_action
                .contains("mark_endpoint_unreachable")
        );
    }

    #[test]
    fn drain_events_clears() {
        let mut store = LeaseStore::new(test_epoch());
        store
            .grant("node-1", LeaseType::RemoteEndpoint, 100, 0, "t")
            .unwrap();
        let e1 = store.drain_events();
        assert_eq!(e1.len(), 1);
        let e2 = store.drain_events();
        assert!(e2.is_empty());
    }

    #[test]
    fn event_counts_track() {
        let mut store = LeaseStore::new(test_epoch());
        let id = store
            .grant("node-1", LeaseType::RemoteEndpoint, 100, 0, "t")
            .unwrap();
        store.renew(&id, 30, "t1").unwrap();
        store.renew(&id, 60, "t2").unwrap();
        store.release(&id, "t3").unwrap();

        assert_eq!(store.event_counts().get("grant"), Some(&1));
        assert_eq!(store.event_counts().get("renew"), Some(&2));
        assert_eq!(store.event_counts().get("release"), Some(&1));
    }

    // -- Serialization round-trips --

    #[test]
    fn lease_id_serialization_round_trip() {
        let id = LeaseId::from_raw(42);
        let json = serde_json::to_string(&id).expect("serialize");
        let restored: LeaseId = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(id, restored);
    }

    #[test]
    fn lease_serialization_round_trip() {
        let lease = Lease {
            lease_id: LeaseId::from_raw(1),
            holder: "node-1".to_string(),
            lease_type: LeaseType::RemoteEndpoint,
            granted_at: 100,
            expires_at: 200,
            ttl: 100,
            epoch: test_epoch(),
            renewal_count: 2,
            status: LeaseStatus::Active,
        };
        let json = serde_json::to_string(&lease).expect("serialize");
        let restored: Lease = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(lease, restored);
    }

    #[test]
    fn lease_event_serialization_round_trip() {
        let event = LeaseEvent {
            lease_id: 1,
            holder: "node-1".to_string(),
            epoch_id: 1,
            ttl: 100,
            status: "active".to_string(),
            escalation_action: String::new(),
            trace_id: "trace-1".to_string(),
            event: "grant".to_string(),
            renewal_count: 0,
        };
        let json = serde_json::to_string(&event).expect("serialize");
        let restored: LeaseEvent = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(event, restored);
    }

    #[test]
    fn lease_error_serialization_round_trip() {
        let errors = vec![
            LeaseError::LeaseNotFound { lease_id: 1 },
            LeaseError::LeaseExpired {
                lease_id: 2,
                expired_at: 100,
            },
            LeaseError::LeaseReleased { lease_id: 3 },
            LeaseError::ZeroTtl,
            LeaseError::EmptyHolder,
        ];
        for err in &errors {
            let json = serde_json::to_string(err).expect("serialize");
            let restored: LeaseError = serde_json::from_str(&json).expect("deserialize");
            assert_eq!(*err, restored);
        }
    }

    #[test]
    fn escalation_action_serialization_round_trip() {
        let actions = vec![
            EscalationAction::MarkEndpointUnreachable {
                holder: "node-1".to_string(),
            },
            EscalationAction::CancelOperation {
                holder: "op-1".to_string(),
            },
            EscalationAction::TerminateSession {
                holder: "sess-1".to_string(),
            },
        ];
        for action in &actions {
            let json = serde_json::to_string(action).expect("serialize");
            let restored: EscalationAction = serde_json::from_str(&json).expect("deserialize");
            assert_eq!(*action, restored);
        }
    }

    // -- Display --

    #[test]
    fn error_display() {
        assert!(LeaseError::ZeroTtl.to_string().contains("non-zero"));
        assert!(LeaseError::EmptyHolder.to_string().contains("non-empty"));
        assert!(
            LeaseError::LeaseNotFound { lease_id: 42 }
                .to_string()
                .contains("42")
        );
    }

    #[test]
    fn escalation_display() {
        assert!(
            EscalationAction::MarkEndpointUnreachable {
                holder: "x".to_string()
            }
            .to_string()
            .contains("mark_endpoint_unreachable")
        );
    }

    // -- Full lifecycle --

    // -- Enrichment: std::error --

    #[test]
    fn lease_error_implements_std_error() {
        let variants: Vec<Box<dyn std::error::Error>> = vec![
            Box::new(LeaseError::LeaseNotFound { lease_id: 1 }),
            Box::new(LeaseError::LeaseExpired {
                lease_id: 2,
                expired_at: 1000,
            }),
            Box::new(LeaseError::LeaseReleased { lease_id: 3 }),
            Box::new(LeaseError::EpochMismatch {
                lease_id: 4,
                lease_epoch: SecurityEpoch::from_raw(1),
                current_epoch: SecurityEpoch::from_raw(3),
            }),
            Box::new(LeaseError::ZeroTtl),
            Box::new(LeaseError::EmptyHolder),
        ];
        let mut displays = std::collections::BTreeSet::new();
        for v in &variants {
            let msg = format!("{v}");
            assert!(!msg.is_empty());
            displays.insert(msg);
        }
        assert_eq!(
            displays.len(),
            6,
            "all 6 variants produce distinct messages"
        );
    }

    #[test]
    fn full_lifecycle_grant_renew_expire_escalate() {
        let mut store = LeaseStore::new(test_epoch());

        // 1. Grant
        let id = store
            .grant("node-1", LeaseType::RemoteEndpoint, 100, 0, "t1")
            .unwrap();

        // 2. Check active
        assert_eq!(store.check(&id, 50).unwrap(), LeaseStatus::Active);

        // 3. Renew
        store.renew(&id, 80, "t2").unwrap();
        let lease = store.get(&id).unwrap();
        assert_eq!(lease.expires_at, 180);

        // 4. Expire (no more renewal)
        assert_eq!(store.check(&id, 200).unwrap(), LeaseStatus::Expired);
        assert_eq!(store.active_count(), 0);

        // 5. Events
        let events = store.drain_events();
        assert!(events.len() >= 2); // grant + renew
    }

    // --- Enrichment tests ---

    #[test]
    fn lease_type_display_uniqueness_btreeset() {
        let types = [
            LeaseType::RemoteEndpoint,
            LeaseType::Operation,
            LeaseType::Session,
        ];
        let displays: std::collections::BTreeSet<String> =
            types.iter().map(|t| t.to_string()).collect();
        assert_eq!(displays.len(), 3);
    }

    #[test]
    fn lease_status_display_uniqueness_btreeset() {
        let statuses = [
            LeaseStatus::Active,
            LeaseStatus::Expired,
            LeaseStatus::Released,
        ];
        let displays: std::collections::BTreeSet<String> =
            statuses.iter().map(|s| s.to_string()).collect();
        assert_eq!(displays.len(), 3);
    }

    #[test]
    fn lease_is_active_at_boundary() {
        let mut store = LeaseStore::new(test_epoch());
        let id = store
            .grant("node-1", LeaseType::RemoteEndpoint, 100, 0, "t")
            .unwrap();
        let lease = store.get(&id).unwrap();
        // Active just before expiration
        assert!(lease.is_active_at(99));
        // Not active at exactly expires_at
        assert!(!lease.is_active_at(100));
    }

    #[test]
    fn lease_id_from_raw_round_trip() {
        let id = LeaseId::from_raw(12345);
        assert_eq!(id.as_u64(), 12345);
        assert_eq!(id.to_string(), "lease:12345");
    }

    #[test]
    fn escalation_action_display_uniqueness_btreeset() {
        let actions = [
            EscalationAction::MarkEndpointUnreachable {
                holder: "a".to_string(),
            },
            EscalationAction::CancelOperation {
                holder: "b".to_string(),
            },
            EscalationAction::TerminateSession {
                holder: "c".to_string(),
            },
        ];
        let displays: std::collections::BTreeSet<String> =
            actions.iter().map(|a| a.to_string()).collect();
        assert_eq!(displays.len(), 3);
    }

    #[test]
    fn lease_serde_roundtrip() {
        let mut store = LeaseStore::new(test_epoch());
        let id = store
            .grant("node-1", LeaseType::RemoteEndpoint, 100, 0, "t1")
            .unwrap();
        let lease = store.get(&id).unwrap();
        let json = serde_json::to_string(lease).unwrap();
        let restored: Lease = serde_json::from_str(&json).unwrap();
        assert_eq!(*lease, restored);
    }

    #[test]
    fn release_already_released_lease_fails() {
        let mut store = LeaseStore::new(test_epoch());
        let id = store
            .grant("node-1", LeaseType::RemoteEndpoint, 100, 0, "t")
            .unwrap();
        store.release(&id, "t-rel1").unwrap();
        let result = store.release(&id, "t-rel2");
        assert!(result.is_err());
    }

    #[test]
    fn epoch_advance_emits_events() {
        let mut store = LeaseStore::new(test_epoch());
        store
            .grant("node-1", LeaseType::RemoteEndpoint, 1000, 0, "t")
            .unwrap();
        store.drain_events();
        store.advance_epoch(SecurityEpoch::from_raw(2), "trace-epoch");
        let events = store.drain_events();
        assert!(!events.is_empty());
    }

    // -- Enrichment: PearlTower 2026-02-26 --

    #[test]
    fn lease_error_serde_epoch_mismatch_variant() {
        let err = LeaseError::EpochMismatch {
            lease_id: 5,
            lease_epoch: SecurityEpoch::from_raw(1),
            current_epoch: SecurityEpoch::from_raw(3),
        };
        let json = serde_json::to_string(&err).unwrap();
        let back: LeaseError = serde_json::from_str(&json).unwrap();
        assert_eq!(err, back);
    }

    #[test]
    fn lease_error_display_epoch_mismatch() {
        let err = LeaseError::EpochMismatch {
            lease_id: 7,
            lease_epoch: SecurityEpoch::from_raw(2),
            current_epoch: SecurityEpoch::from_raw(5),
        };
        let msg = err.to_string();
        assert!(msg.contains("7"), "should contain lease_id");
        assert!(msg.contains("epoch mismatch"), "should describe the error");
    }

    #[test]
    fn renewal_due_at_with_ttl_one() {
        let lease = Lease {
            lease_id: LeaseId::from_raw(1),
            holder: "h".to_string(),
            lease_type: LeaseType::Operation,
            granted_at: 100,
            expires_at: 101,
            ttl: 1,
            epoch: test_epoch(),
            renewal_count: 0,
            status: LeaseStatus::Active,
        };
        // ttl/3 = 0, so renewal_due_at = expires_at - ttl + 0 = 100
        assert_eq!(lease.renewal_due_at(), 100);
    }

    #[test]
    fn is_active_at_after_release_returns_false() {
        let lease = Lease {
            lease_id: LeaseId::from_raw(1),
            holder: "h".to_string(),
            lease_type: LeaseType::Operation,
            granted_at: 0,
            expires_at: 1000,
            ttl: 1000,
            epoch: test_epoch(),
            renewal_count: 0,
            status: LeaseStatus::Released,
        };
        // Even though time hasn't expired, status is Released.
        assert!(!lease.is_active_at(500));
    }

    #[test]
    fn scan_expired_with_no_expired_leases() {
        let mut store = LeaseStore::new(test_epoch());
        store
            .grant("node-1", LeaseType::RemoteEndpoint, 1000, 0, "t")
            .unwrap();
        let actions = store.scan_expired(500, "trace-scan");
        assert!(actions.is_empty());
        assert_eq!(store.active_count(), 1);
    }

    #[test]
    fn event_counts_include_expiration() {
        let mut store = LeaseStore::new(test_epoch());
        store
            .grant("node-1", LeaseType::RemoteEndpoint, 100, 0, "t")
            .unwrap();
        store.scan_expired(200, "trace-scan");
        assert_eq!(store.event_counts().get("expiration"), Some(&1));
    }

    #[test]
    fn epoch_accessor_returns_current() {
        let mut store = LeaseStore::new(SecurityEpoch::from_raw(42));
        assert_eq!(store.epoch(), SecurityEpoch::from_raw(42));
        store.advance_epoch(SecurityEpoch::from_raw(99), "t");
        assert_eq!(store.epoch(), SecurityEpoch::from_raw(99));
    }

    #[test]
    fn total_count_vs_active_count_after_expiration() {
        let mut store = LeaseStore::new(test_epoch());
        store
            .grant("node-1", LeaseType::RemoteEndpoint, 100, 0, "t1")
            .unwrap();
        store
            .grant("node-2", LeaseType::Operation, 200, 0, "t2")
            .unwrap();
        store.scan_expired(150, "t-scan");
        // node-1 expired (ttl 100), node-2 still active (ttl 200)
        assert_eq!(store.total_count(), 2);
        assert_eq!(store.active_count(), 1);
    }

    #[test]
    fn advance_epoch_same_epoch_is_noop() {
        let mut store = LeaseStore::new(test_epoch());
        store
            .grant("node-1", LeaseType::RemoteEndpoint, 1000, 0, "t")
            .unwrap();
        let actions = store.advance_epoch(test_epoch(), "t-same");
        assert!(actions.is_empty());
        assert_eq!(store.active_count(), 1);
    }

    #[test]
    fn grant_increments_ids_monotonically() {
        let mut store = LeaseStore::new(test_epoch());
        let id1 = store
            .grant("a", LeaseType::RemoteEndpoint, 100, 0, "t")
            .unwrap();
        let id2 = store.grant("b", LeaseType::Operation, 100, 0, "t").unwrap();
        let id3 = store.grant("c", LeaseType::Session, 100, 0, "t").unwrap();
        assert_eq!(id1.as_u64(), 1);
        assert_eq!(id2.as_u64(), 2);
        assert_eq!(id3.as_u64(), 3);
    }

    #[test]
    fn lease_serde_with_expired_status() {
        let lease = Lease {
            lease_id: LeaseId::from_raw(1),
            holder: "h".to_string(),
            lease_type: LeaseType::Session,
            granted_at: 0,
            expires_at: 100,
            ttl: 100,
            epoch: test_epoch(),
            renewal_count: 0,
            status: LeaseStatus::Expired,
        };
        let json = serde_json::to_string(&lease).unwrap();
        let back: Lease = serde_json::from_str(&json).unwrap();
        assert_eq!(back.status, LeaseStatus::Expired);
    }

    #[test]
    fn lease_serde_with_released_status() {
        let lease = Lease {
            lease_id: LeaseId::from_raw(1),
            holder: "h".to_string(),
            lease_type: LeaseType::Operation,
            granted_at: 0,
            expires_at: 100,
            ttl: 100,
            epoch: test_epoch(),
            renewal_count: 3,
            status: LeaseStatus::Released,
        };
        let json = serde_json::to_string(&lease).unwrap();
        let back: Lease = serde_json::from_str(&json).unwrap();
        assert_eq!(back.status, LeaseStatus::Released);
        assert_eq!(back.renewal_count, 3);
    }

    #[test]
    fn lease_type_serde_all_variants() {
        for lt in [
            LeaseType::RemoteEndpoint,
            LeaseType::Operation,
            LeaseType::Session,
        ] {
            let json = serde_json::to_string(&lt).unwrap();
            let back: LeaseType = serde_json::from_str(&json).unwrap();
            assert_eq!(lt, back);
        }
    }

    #[test]
    fn lease_status_serde_all_variants() {
        for status in [
            LeaseStatus::Active,
            LeaseStatus::Expired,
            LeaseStatus::Released,
        ] {
            let json = serde_json::to_string(&status).unwrap();
            let back: LeaseStatus = serde_json::from_str(&json).unwrap();
            assert_eq!(status, back);
        }
    }

    #[test]
    fn escalation_action_display_includes_holder() {
        let a1 = EscalationAction::MarkEndpointUnreachable {
            holder: "my-node".to_string(),
        };
        assert!(a1.to_string().contains("my-node"));
        let a2 = EscalationAction::CancelOperation {
            holder: "my-op".to_string(),
        };
        assert!(a2.to_string().contains("my-op"));
        let a3 = EscalationAction::TerminateSession {
            holder: "my-sess".to_string(),
        };
        assert!(a3.to_string().contains("my-sess"));
    }

    // -- Enrichment: PearlTower 2026-03-02 --

    #[test]
    fn enrichment_lease_id_ord_determinism_in_btreeset() {
        use std::collections::BTreeSet;
        let ids: BTreeSet<LeaseId> = (0..5).rev().map(LeaseId::from_raw).collect();
        let ordered: Vec<u64> = ids.iter().map(|id| id.as_u64()).collect();
        assert_eq!(
            ordered,
            vec![0, 1, 2, 3, 4],
            "LeaseId Ord must sort by raw u64"
        );
    }

    #[test]
    fn enrichment_lease_id_clone_independence() {
        let original = LeaseId::from_raw(77);
        let cloned = original.clone();
        assert_eq!(original, cloned);
        // They are distinct allocations (struct identity, not ref equality).
        assert_eq!(cloned.as_u64(), 77);
    }

    #[test]
    fn enrichment_lease_id_hash_in_btreeset_dedup() {
        use std::collections::BTreeSet;
        let mut set = BTreeSet::new();
        set.insert(LeaseId::from_raw(10));
        set.insert(LeaseId::from_raw(10));
        set.insert(LeaseId::from_raw(20));
        assert_eq!(set.len(), 2, "duplicate LeaseId should be deduplicated");
    }

    #[test]
    fn enrichment_lease_id_display_zero() {
        assert_eq!(LeaseId::from_raw(0).to_string(), "lease:0");
    }

    #[test]
    fn enrichment_lease_id_display_u64_max() {
        let id = LeaseId::from_raw(u64::MAX);
        let s = id.to_string();
        assert_eq!(s, format!("lease:{}", u64::MAX));
        assert_eq!(id.as_u64(), u64::MAX);
    }

    #[test]
    fn enrichment_lease_type_copy_semantics() {
        let t = LeaseType::Session;
        let copy = t;
        // Both are usable after copy — proves Copy semantics.
        assert_eq!(t, copy);
        assert_eq!(t.to_string(), copy.to_string());
    }

    #[test]
    fn enrichment_lease_type_ord_determinism() {
        // Derive order follows declaration: RemoteEndpoint < Operation < Session.
        assert!(LeaseType::RemoteEndpoint < LeaseType::Operation);
        assert!(LeaseType::Operation < LeaseType::Session);
    }

    #[test]
    fn enrichment_lease_status_copy_semantics() {
        let s = LeaseStatus::Expired;
        let copy = s;
        assert_eq!(s, copy);
        assert_eq!(s.to_string(), "expired");
    }

    #[test]
    fn enrichment_lease_status_ord_determinism() {
        // Derive order follows declaration: Active < Expired < Released.
        assert!(LeaseStatus::Active < LeaseStatus::Expired);
        assert!(LeaseStatus::Expired < LeaseStatus::Released);
    }

    #[test]
    fn enrichment_lease_json_field_names() {
        let lease = Lease {
            lease_id: LeaseId::from_raw(1),
            holder: "h".to_string(),
            lease_type: LeaseType::Operation,
            granted_at: 10,
            expires_at: 110,
            ttl: 100,
            epoch: test_epoch(),
            renewal_count: 5,
            status: LeaseStatus::Active,
        };
        let json = serde_json::to_string(&lease).unwrap();
        for field in [
            "lease_id",
            "holder",
            "lease_type",
            "granted_at",
            "expires_at",
            "ttl",
            "epoch",
            "renewal_count",
            "status",
        ] {
            assert!(json.contains(field), "JSON must contain field '{field}'");
        }
    }

    #[test]
    fn enrichment_lease_event_json_field_names() {
        let event = LeaseEvent {
            lease_id: 1,
            holder: "h".to_string(),
            epoch_id: 2,
            ttl: 100,
            status: "active".to_string(),
            escalation_action: "none".to_string(),
            trace_id: "t".to_string(),
            event: "grant".to_string(),
            renewal_count: 0,
        };
        let json = serde_json::to_string(&event).unwrap();
        for field in [
            "lease_id",
            "holder",
            "epoch_id",
            "ttl",
            "status",
            "escalation_action",
            "trace_id",
            "event",
            "renewal_count",
        ] {
            assert!(
                json.contains(field),
                "LeaseEvent JSON must contain field '{field}'"
            );
        }
    }

    #[test]
    fn enrichment_lease_event_clone_eq() {
        let event = LeaseEvent {
            lease_id: 42,
            holder: "node-x".to_string(),
            epoch_id: 3,
            ttl: 500,
            status: "expired".to_string(),
            escalation_action: "cancel_operation(node-x)".to_string(),
            trace_id: "trace-99".to_string(),
            event: "expiration".to_string(),
            renewal_count: 7,
        };
        let cloned = event.clone();
        assert_eq!(event, cloned);
    }

    #[test]
    fn enrichment_escalation_action_clone_eq() {
        let action = EscalationAction::CancelOperation {
            holder: "op-42".to_string(),
        };
        let cloned = action.clone();
        assert_eq!(action, cloned);
        // Different holder -> not equal.
        let other = EscalationAction::CancelOperation {
            holder: "op-99".to_string(),
        };
        assert_ne!(action, other);
    }

    #[test]
    fn enrichment_escalation_action_display_exact_format() {
        assert_eq!(
            EscalationAction::MarkEndpointUnreachable {
                holder: "n1".to_string()
            }
            .to_string(),
            "mark_endpoint_unreachable(n1)"
        );
        assert_eq!(
            EscalationAction::CancelOperation {
                holder: "op".to_string()
            }
            .to_string(),
            "cancel_operation(op)"
        );
        assert_eq!(
            EscalationAction::TerminateSession {
                holder: "s".to_string()
            }
            .to_string(),
            "terminate_session(s)"
        );
    }

    #[test]
    fn enrichment_lease_error_display_exact_formats() {
        assert_eq!(
            LeaseError::LeaseNotFound { lease_id: 42 }.to_string(),
            "lease 42 not found"
        );
        assert_eq!(
            LeaseError::LeaseExpired {
                lease_id: 5,
                expired_at: 300
            }
            .to_string(),
            "lease 5 expired at tick 300"
        );
        assert_eq!(
            LeaseError::LeaseReleased { lease_id: 9 }.to_string(),
            "lease 9 already released"
        );
        assert_eq!(LeaseError::ZeroTtl.to_string(), "TTL must be non-zero");
        assert_eq!(
            LeaseError::EmptyHolder.to_string(),
            "holder must be non-empty"
        );
    }

    #[test]
    fn enrichment_scan_expired_does_not_escalate_released_leases() {
        let mut store = LeaseStore::new(test_epoch());
        let id = store
            .grant("node-1", LeaseType::RemoteEndpoint, 100, 0, "t")
            .unwrap();
        // Release before expiration.
        store.release(&id, "t-rel").unwrap();
        store.drain_events();
        // Scan well past the original expiration.
        let actions = store.scan_expired(500, "trace-scan");
        assert!(
            actions.is_empty(),
            "released leases must not trigger escalation"
        );
    }

    #[test]
    fn enrichment_advance_epoch_preserves_leases_granted_in_new_epoch() {
        let mut store = LeaseStore::new(test_epoch());
        // Grant in epoch 1, then advance to epoch 2.
        store
            .grant("old", LeaseType::RemoteEndpoint, 1000, 0, "t1")
            .unwrap();
        store.advance_epoch(SecurityEpoch::from_raw(2), "t-adv");
        // Now grant in epoch 2.
        let new_id = store
            .grant("new", LeaseType::Operation, 500, 100, "t2")
            .unwrap();
        // Advance to epoch 3 — only the new-epoch lease should survive if it
        // were in epoch 2. Actually it should be invalidated because epoch changed to 3.
        let actions = store.advance_epoch(SecurityEpoch::from_raw(3), "t-adv2");
        // The "new" lease was granted in epoch 2, so it gets invalidated.
        assert_eq!(actions.len(), 1);
        assert!(matches!(
            &actions[0],
            EscalationAction::CancelOperation { holder } if holder == "new"
        ));
        // "old" was already expired from the first advance.
        let old_lease = store.get(&LeaseId::from_raw(1)).unwrap();
        assert_eq!(old_lease.status, LeaseStatus::Expired);
        let new_lease = store.get(&new_id).unwrap();
        assert_eq!(new_lease.status, LeaseStatus::Expired);
    }

    #[test]
    fn enrichment_renewal_due_at_large_ttl() {
        let lease = Lease {
            lease_id: LeaseId::from_raw(1),
            holder: "h".to_string(),
            lease_type: LeaseType::RemoteEndpoint,
            granted_at: 0,
            expires_at: u64::MAX,
            ttl: u64::MAX,
            epoch: test_epoch(),
            renewal_count: 0,
            status: LeaseStatus::Active,
        };
        // renewal_due_at = expires_at.saturating_sub(ttl) + ttl/3
        //                = 0 + u64::MAX/3
        let expected = u64::MAX / 3;
        assert_eq!(lease.renewal_due_at(), expected);
    }

    #[test]
    fn enrichment_grant_at_nonzero_tick_sets_correct_window() {
        let mut store = LeaseStore::new(test_epoch());
        let id = store
            .grant("node-1", LeaseType::Session, 200, 1000, "t")
            .unwrap();
        let lease = store.get(&id).unwrap();
        assert_eq!(lease.granted_at, 1000);
        assert_eq!(lease.expires_at, 1200);
        assert!(lease.is_active_at(1199));
        assert!(!lease.is_active_at(1200));
    }

    #[test]
    fn enrichment_renew_at_exact_boundary_before_expiry() {
        let mut store = LeaseStore::new(test_epoch());
        let id = store
            .grant("node-1", LeaseType::RemoteEndpoint, 100, 0, "t")
            .unwrap();
        // Renew at tick 99, the last valid tick (expires_at=100, so 99 < 100).
        store.renew(&id, 99, "t-renew").unwrap();
        let lease = store.get(&id).unwrap();
        assert_eq!(lease.expires_at, 199); // 99 + 100
        assert_eq!(lease.renewal_count, 1);
    }

    #[test]
    fn enrichment_renew_at_exact_expiry_tick_fails() {
        let mut store = LeaseStore::new(test_epoch());
        let id = store
            .grant("node-1", LeaseType::RemoteEndpoint, 100, 0, "t")
            .unwrap();
        // Renew at exactly expires_at (100) should fail — the lease is expired.
        let err = store.renew(&id, 100, "t-renew").unwrap_err();
        assert!(matches!(
            err,
            LeaseError::LeaseExpired {
                lease_id: 1,
                expired_at: 100
            }
        ));
        // Status should now be Expired.
        let lease = store.get(&id).unwrap();
        assert_eq!(lease.status, LeaseStatus::Expired);
    }

    #[test]
    fn enrichment_epoch_invalidation_event_counts() {
        let mut store = LeaseStore::new(test_epoch());
        store
            .grant("a", LeaseType::RemoteEndpoint, 1000, 0, "t")
            .unwrap();
        store
            .grant("b", LeaseType::Operation, 1000, 0, "t")
            .unwrap();
        store.grant("c", LeaseType::Session, 1000, 0, "t").unwrap();
        store.advance_epoch(SecurityEpoch::from_raw(2), "t-adv");
        assert_eq!(
            store.event_counts().get("epoch_invalidation"),
            Some(&3),
            "all 3 leases should produce epoch_invalidation events"
        );
    }
}
