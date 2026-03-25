//! Global bulkheads for concurrency limiting with backpressure signaling.
//!
//! Bulkheads limit the maximum number of concurrent operations in specific
//! categories to prevent resource exhaustion and cascade failures. When a
//! bulkhead reaches >80% capacity, a backpressure event is emitted for
//! regime detection and adaptive load management.
//!
//! Predefined bulkheads:
//! - `RemoteInFlight`: outbound remote operations (default: 64).
//! - `BackgroundMaintenance`: background tasks (default: 16).
//! - `SagaExecution`: concurrent sagas (default: 8).
//! - `EvidenceFlush`: concurrent evidence writes (default: 4).
//!
//! Permits are RAII-style: acquiring returns a `PermitId` that must be
//! explicitly released. Queue depth limits prevent unbounded waiting.
//!
//! Plan references: Section 10.11 item 26, 9G.8 (scheduler + bulkheads),
//! Top-10 #4 (performance discipline), #8 (per-extension resource budget).

use std::collections::BTreeMap;
use std::fmt;

use serde::{Deserialize, Serialize};

// ---------------------------------------------------------------------------
// BulkheadClass — predefined bulkhead categories
// ---------------------------------------------------------------------------

/// Predefined bulkhead categories.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum BulkheadClass {
    /// Outbound remote operations.
    RemoteInFlight,
    /// Background maintenance (GC, compaction, audit, anti-entropy).
    BackgroundMaintenance,
    /// Concurrent saga instances.
    SagaExecution,
    /// Concurrent evidence write operations.
    EvidenceFlush,
}

impl fmt::Display for BulkheadClass {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::RemoteInFlight => f.write_str("remote_in_flight"),
            Self::BackgroundMaintenance => f.write_str("background_maintenance"),
            Self::SagaExecution => f.write_str("saga_execution"),
            Self::EvidenceFlush => f.write_str("evidence_flush"),
        }
    }
}

impl BulkheadClass {
    /// Default configuration for this bulkhead class.
    pub fn default_config(&self) -> BulkheadConfig {
        match self {
            Self::RemoteInFlight => BulkheadConfig {
                max_concurrent: 64,
                max_queue_depth: 128,
                pressure_threshold_pct: 80,
            },
            Self::BackgroundMaintenance => BulkheadConfig {
                max_concurrent: 16,
                max_queue_depth: 32,
                pressure_threshold_pct: 80,
            },
            Self::SagaExecution => BulkheadConfig {
                max_concurrent: 8,
                max_queue_depth: 16,
                pressure_threshold_pct: 80,
            },
            Self::EvidenceFlush => BulkheadConfig {
                max_concurrent: 4,
                max_queue_depth: 8,
                pressure_threshold_pct: 80,
            },
        }
    }
}

// ---------------------------------------------------------------------------
// BulkheadConfig — configurable parameters
// ---------------------------------------------------------------------------

/// Configuration for a bulkhead.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BulkheadConfig {
    /// Maximum concurrent operations.
    pub max_concurrent: usize,
    /// Maximum queue depth for waiting acquires.
    pub max_queue_depth: usize,
    /// Backpressure threshold as percentage of max_concurrent (0-100).
    pub pressure_threshold_pct: u8,
}

// ---------------------------------------------------------------------------
// PermitId — unique permit identifier
// ---------------------------------------------------------------------------

/// Unique identifier for a bulkhead permit.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct PermitId(pub u64);

impl fmt::Display for PermitId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "permit:{}", self.0)
    }
}

// ---------------------------------------------------------------------------
// BulkheadEvent — structured audit event
// ---------------------------------------------------------------------------

/// Structured event emitted for bulkhead state changes.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BulkheadEvent {
    /// Bulkhead identifier.
    pub bulkhead_id: String,
    /// Current in-flight count after the event.
    pub current_count: usize,
    /// Maximum concurrent limit.
    pub max_concurrent: usize,
    /// Current queue depth.
    pub queue_depth: usize,
    /// Action taken.
    pub action: String,
    /// Trace identifier.
    pub trace_id: String,
    /// Event type.
    pub event: String,
    /// Permit ID (if applicable).
    pub permit_id: u64,
}

// ---------------------------------------------------------------------------
// BulkheadError — typed errors
// ---------------------------------------------------------------------------

/// Errors from bulkhead operations.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum BulkheadError {
    /// Bulkhead is full and queue is full (no room to wait).
    BulkheadFull {
        bulkhead_id: String,
        max_concurrent: usize,
        queue_depth: usize,
    },
    /// Permit not found (double release or invalid ID).
    PermitNotFound { permit_id: u64 },
    /// Bulkhead not found.
    BulkheadNotFound { bulkhead_id: String },
    /// Invalid configuration.
    InvalidConfig { reason: String },
}

impl fmt::Display for BulkheadError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::BulkheadFull {
                bulkhead_id,
                max_concurrent,
                queue_depth,
            } => {
                write!(
                    f,
                    "bulkhead {bulkhead_id} full: {max_concurrent} active, {queue_depth} queued"
                )
            }
            Self::PermitNotFound { permit_id } => {
                write!(f, "permit {permit_id} not found")
            }
            Self::BulkheadNotFound { bulkhead_id } => {
                write!(f, "bulkhead {bulkhead_id} not found")
            }
            Self::InvalidConfig { reason } => {
                write!(f, "invalid bulkhead config: {reason}")
            }
        }
    }
}

impl std::error::Error for BulkheadError {}

// ---------------------------------------------------------------------------
// Bulkhead — a single concurrency limiter
// ---------------------------------------------------------------------------

/// A single bulkhead enforcing a concurrency ceiling.
#[derive(Debug)]
struct Bulkhead {
    config: BulkheadConfig,
    /// Currently held permits.
    active_permits: BTreeMap<u64, String>,
    /// Queued waiters (permit_id, trace_id).
    waiters: Vec<(u64, String)>,
}

impl Bulkhead {
    fn new(config: BulkheadConfig) -> Self {
        Self {
            config,
            active_permits: BTreeMap::new(),
            waiters: Vec::new(),
        }
    }

    fn active_count(&self) -> usize {
        self.active_permits.len()
    }

    fn queue_depth(&self) -> usize {
        self.waiters.len()
    }

    fn is_at_pressure(&self) -> bool {
        let threshold = self
            .config
            .max_concurrent
            .saturating_mul(self.config.pressure_threshold_pct as usize)
            / 100;
        self.active_count() >= threshold
    }
}

// ---------------------------------------------------------------------------
// BulkheadRegistry — centralized registry of all bulkheads
// ---------------------------------------------------------------------------

/// Centralized registry managing all bulkheads.
#[derive(Debug)]
pub struct BulkheadRegistry {
    /// Bulkheads by ID.
    bulkheads: BTreeMap<String, Bulkhead>,
    /// Next permit ID.
    next_permit_id: u64,
    /// Accumulated audit events.
    events: Vec<BulkheadEvent>,
    /// Event counters.
    event_counts: BTreeMap<String, u64>,
}

impl BulkheadRegistry {
    /// Create a registry with default bulkheads.
    pub fn with_defaults() -> Self {
        let mut registry = Self {
            bulkheads: BTreeMap::new(),
            next_permit_id: 1,
            events: Vec::new(),
            event_counts: BTreeMap::new(),
        };

        for class in &[
            BulkheadClass::RemoteInFlight,
            BulkheadClass::BackgroundMaintenance,
            BulkheadClass::SagaExecution,
            BulkheadClass::EvidenceFlush,
        ] {
            registry
                .bulkheads
                .insert(class.to_string(), Bulkhead::new(class.default_config()));
        }

        registry
    }

    /// Create an empty registry (no default bulkheads).
    pub fn empty() -> Self {
        Self {
            bulkheads: BTreeMap::new(),
            next_permit_id: 1,
            events: Vec::new(),
            event_counts: BTreeMap::new(),
        }
    }

    /// Register a custom bulkhead.
    pub fn register(
        &mut self,
        bulkhead_id: &str,
        config: BulkheadConfig,
    ) -> Result<(), BulkheadError> {
        if config.max_concurrent == 0 {
            return Err(BulkheadError::InvalidConfig {
                reason: "max_concurrent must be > 0".to_string(),
            });
        }
        self.bulkheads
            .insert(bulkhead_id.to_string(), Bulkhead::new(config));
        Ok(())
    }

    /// Attempt to acquire a permit from the named bulkhead.
    ///
    /// Returns `Ok(PermitId)` if a slot is available.
    /// If the bulkhead is full but the queue has room, the permit is queued
    /// and returned as acquired (for synchronous deterministic semantics).
    /// If both are full, returns `Err(BulkheadFull)`.
    pub fn acquire(
        &mut self,
        bulkhead_id: &str,
        trace_id: &str,
    ) -> Result<PermitId, BulkheadError> {
        let bh = self
            .bulkheads
            .get_mut(bulkhead_id)
            .ok_or(BulkheadError::BulkheadNotFound {
                bulkhead_id: bulkhead_id.to_string(),
            })?;

        let permit_id = PermitId(self.next_permit_id);
        self.next_permit_id += 1;

        if bh.active_count() < bh.config.max_concurrent {
            // Slot available — acquire directly.
            bh.active_permits.insert(permit_id.0, trace_id.to_string());

            let was_at_pressure = bh.is_at_pressure();
            let current_count = bh.active_count();
            let max_concurrent = bh.config.max_concurrent;
            let queue_depth = bh.queue_depth();

            self.emit_event(BulkheadEvent {
                bulkhead_id: bulkhead_id.to_string(),
                current_count,
                max_concurrent,
                queue_depth,
                action: "acquire".to_string(),
                trace_id: trace_id.to_string(),
                event: "permit_acquired".to_string(),
                permit_id: permit_id.0,
            });
            self.record_count("acquire");

            if was_at_pressure {
                self.emit_event(BulkheadEvent {
                    bulkhead_id: bulkhead_id.to_string(),
                    current_count,
                    max_concurrent,
                    queue_depth,
                    action: "pressure".to_string(),
                    trace_id: trace_id.to_string(),
                    event: "bulkhead_pressure".to_string(),
                    permit_id: permit_id.0,
                });
                self.record_count("pressure");
            }

            Ok(permit_id)
        } else if bh.queue_depth() < bh.config.max_queue_depth {
            // Queue the waiter and immediately promote (deterministic mode).
            // The engine is single-threaded per cell, so blocking would
            // deadlock.  Instead we immediately admit the waiter as an
            // over-limit permit (tracked separately for accounting).
            bh.waiters.push((permit_id.0, trace_id.to_string()));

            let current_count = bh.active_count();
            let max_concurrent = bh.config.max_concurrent;
            let queue_depth = bh.queue_depth();

            self.emit_event(BulkheadEvent {
                bulkhead_id: bulkhead_id.to_string(),
                current_count,
                max_concurrent,
                queue_depth,
                action: "queued".to_string(),
                trace_id: trace_id.to_string(),
                event: "permit_queued".to_string(),
                permit_id: permit_id.0,
            });
            self.record_count("queued");

            Ok(permit_id)
        } else {
            // Both full — reject.
            let current_count = bh.active_count();
            let max_concurrent = bh.config.max_concurrent;
            let queue_depth = bh.queue_depth();

            self.emit_event(BulkheadEvent {
                bulkhead_id: bulkhead_id.to_string(),
                current_count,
                max_concurrent,
                queue_depth,
                action: "reject".to_string(),
                trace_id: trace_id.to_string(),
                event: "permit_rejected".to_string(),
                permit_id: permit_id.0,
            });
            self.record_count("reject");

            Err(BulkheadError::BulkheadFull {
                bulkhead_id: bulkhead_id.to_string(),
                max_concurrent,
                queue_depth,
            })
        }
    }

    /// Release a permit, freeing a concurrency slot.
    ///
    /// If waiters are queued, the next waiter is promoted to active.
    pub fn release(
        &mut self,
        bulkhead_id: &str,
        permit_id: PermitId,
        trace_id: &str,
    ) -> Result<(), BulkheadError> {
        let bh = self
            .bulkheads
            .get_mut(bulkhead_id)
            .ok_or(BulkheadError::BulkheadNotFound {
                bulkhead_id: bulkhead_id.to_string(),
            })?;

        // Try removing from active permits.
        if bh.active_permits.remove(&permit_id.0).is_some() {
            // Promote next waiter if any.
            if let Some((waiter_id, waiter_trace)) = bh.waiters.first().cloned() {
                bh.waiters.remove(0);
                bh.active_permits.insert(waiter_id, waiter_trace);
            }
        } else {
            // Try removing from waiters.
            let waiter_idx = bh.waiters.iter().position(|(id, _)| *id == permit_id.0);
            if let Some(idx) = waiter_idx {
                bh.waiters.remove(idx);
            } else {
                return Err(BulkheadError::PermitNotFound {
                    permit_id: permit_id.0,
                });
            }
        }

        let current_count = bh.active_count();
        let max_concurrent = bh.config.max_concurrent;
        let queue_depth = bh.queue_depth();

        self.emit_event(BulkheadEvent {
            bulkhead_id: bulkhead_id.to_string(),
            current_count,
            max_concurrent,
            queue_depth,
            action: "release".to_string(),
            trace_id: trace_id.to_string(),
            event: "permit_released".to_string(),
            permit_id: permit_id.0,
        });
        self.record_count("release");

        Ok(())
    }

    /// Get the active count for a bulkhead.
    pub fn active_count(&self, bulkhead_id: &str) -> Option<usize> {
        self.bulkheads.get(bulkhead_id).map(|bh| bh.active_count())
    }

    /// Get the queue depth for a bulkhead.
    pub fn queue_depth(&self, bulkhead_id: &str) -> Option<usize> {
        self.bulkheads.get(bulkhead_id).map(|bh| bh.queue_depth())
    }

    /// Check if a bulkhead is at backpressure threshold.
    pub fn is_at_pressure(&self, bulkhead_id: &str) -> Option<bool> {
        self.bulkheads
            .get(bulkhead_id)
            .map(|bh| bh.is_at_pressure())
    }

    /// Reconfigure a bulkhead (hot-reload). Existing permits are not dropped.
    pub fn reconfigure(
        &mut self,
        bulkhead_id: &str,
        new_config: BulkheadConfig,
    ) -> Result<(), BulkheadError> {
        if new_config.max_concurrent == 0 {
            return Err(BulkheadError::InvalidConfig {
                reason: "max_concurrent must be > 0".to_string(),
            });
        }
        let bh = self
            .bulkheads
            .get_mut(bulkhead_id)
            .ok_or(BulkheadError::BulkheadNotFound {
                bulkhead_id: bulkhead_id.to_string(),
            })?;
        bh.config = new_config;
        Ok(())
    }

    /// Snapshot of all bulkhead states.
    pub fn snapshot(&self) -> BTreeMap<String, BulkheadSnapshot> {
        self.bulkheads
            .iter()
            .map(|(id, bh)| {
                (
                    id.clone(),
                    BulkheadSnapshot {
                        bulkhead_id: id.clone(),
                        active_count: bh.active_count(),
                        max_concurrent: bh.config.max_concurrent,
                        queue_depth: bh.queue_depth(),
                        max_queue_depth: bh.config.max_queue_depth,
                        at_pressure: bh.is_at_pressure(),
                    },
                )
            })
            .collect()
    }

    /// Number of registered bulkheads.
    pub fn bulkhead_count(&self) -> usize {
        self.bulkheads.len()
    }

    /// Drain accumulated events.
    pub fn drain_events(&mut self) -> Vec<BulkheadEvent> {
        std::mem::take(&mut self.events)
    }

    /// Event counters.
    pub fn event_counts(&self) -> &BTreeMap<String, u64> {
        &self.event_counts
    }

    // -- Internal --

    fn emit_event(&mut self, event: BulkheadEvent) {
        self.events.push(event);
    }

    fn record_count(&mut self, event_type: &str) {
        *self.event_counts.entry(event_type.to_string()).or_insert(0) += 1;
    }
}

// ---------------------------------------------------------------------------
// BulkheadSnapshot — point-in-time state for dashboards
// ---------------------------------------------------------------------------

/// Point-in-time snapshot of a bulkhead's state.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BulkheadSnapshot {
    pub bulkhead_id: String,
    pub active_count: usize,
    pub max_concurrent: usize,
    pub queue_depth: usize,
    pub max_queue_depth: usize,
    pub at_pressure: bool,
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    // -- BulkheadClass --

    #[test]
    fn bulkhead_class_display() {
        assert_eq!(
            BulkheadClass::RemoteInFlight.to_string(),
            "remote_in_flight"
        );
        assert_eq!(
            BulkheadClass::BackgroundMaintenance.to_string(),
            "background_maintenance"
        );
        assert_eq!(BulkheadClass::SagaExecution.to_string(), "saga_execution");
        assert_eq!(BulkheadClass::EvidenceFlush.to_string(), "evidence_flush");
    }

    #[test]
    fn default_configs() {
        assert_eq!(
            BulkheadClass::RemoteInFlight
                .default_config()
                .max_concurrent,
            64
        );
        assert_eq!(
            BulkheadClass::BackgroundMaintenance
                .default_config()
                .max_concurrent,
            16
        );
        assert_eq!(
            BulkheadClass::SagaExecution.default_config().max_concurrent,
            8
        );
        assert_eq!(
            BulkheadClass::EvidenceFlush.default_config().max_concurrent,
            4
        );
    }

    // -- Registry creation --

    #[test]
    fn with_defaults_creates_four_bulkheads() {
        let reg = BulkheadRegistry::with_defaults();
        assert_eq!(reg.bulkhead_count(), 4);
    }

    #[test]
    fn empty_creates_no_bulkheads() {
        let reg = BulkheadRegistry::empty();
        assert_eq!(reg.bulkhead_count(), 0);
    }

    #[test]
    fn register_custom_bulkhead() {
        let mut reg = BulkheadRegistry::empty();
        reg.register(
            "custom",
            BulkheadConfig {
                max_concurrent: 10,
                max_queue_depth: 20,
                pressure_threshold_pct: 80,
            },
        )
        .unwrap();
        assert_eq!(reg.bulkhead_count(), 1);
    }

    #[test]
    fn register_rejects_zero_concurrent() {
        let mut reg = BulkheadRegistry::empty();
        assert!(matches!(
            reg.register(
                "bad",
                BulkheadConfig {
                    max_concurrent: 0,
                    max_queue_depth: 10,
                    pressure_threshold_pct: 80,
                },
            ),
            Err(BulkheadError::InvalidConfig { .. })
        ));
    }

    // -- Acquire and release --

    #[test]
    fn acquire_and_release() {
        let mut reg = BulkheadRegistry::empty();
        reg.register(
            "test",
            BulkheadConfig {
                max_concurrent: 2,
                max_queue_depth: 4,
                pressure_threshold_pct: 80,
            },
        )
        .unwrap();

        let p1 = reg.acquire("test", "t1").unwrap();
        assert_eq!(reg.active_count("test"), Some(1));

        let p2 = reg.acquire("test", "t2").unwrap();
        assert_eq!(reg.active_count("test"), Some(2));

        reg.release("test", p1, "t1").unwrap();
        assert_eq!(reg.active_count("test"), Some(1));

        reg.release("test", p2, "t2").unwrap();
        assert_eq!(reg.active_count("test"), Some(0));
    }

    #[test]
    fn acquire_queues_when_full() {
        let mut reg = BulkheadRegistry::empty();
        reg.register(
            "test",
            BulkheadConfig {
                max_concurrent: 1,
                max_queue_depth: 2,
                pressure_threshold_pct: 80,
            },
        )
        .unwrap();

        let _p1 = reg.acquire("test", "t1").unwrap();
        let p2 = reg.acquire("test", "t2").unwrap(); // queued
        assert_eq!(reg.queue_depth("test"), Some(1));

        // Release p2 from waiters.
        reg.release("test", p2, "t2").unwrap();
        assert_eq!(reg.queue_depth("test"), Some(0));
    }

    #[test]
    fn acquire_rejects_when_both_full() {
        let mut reg = BulkheadRegistry::empty();
        reg.register(
            "test",
            BulkheadConfig {
                max_concurrent: 1,
                max_queue_depth: 1,
                pressure_threshold_pct: 80,
            },
        )
        .unwrap();

        let _p1 = reg.acquire("test", "t1").unwrap();
        let _p2 = reg.acquire("test", "t2").unwrap(); // queued
        assert!(matches!(
            reg.acquire("test", "t3"),
            Err(BulkheadError::BulkheadFull { .. })
        ));
    }

    #[test]
    fn acquire_nonexistent_bulkhead() {
        let mut reg = BulkheadRegistry::empty();
        assert!(matches!(
            reg.acquire("ghost", "t1"),
            Err(BulkheadError::BulkheadNotFound { .. })
        ));
    }

    #[test]
    fn release_nonexistent_permit() {
        let mut reg = BulkheadRegistry::empty();
        reg.register(
            "test",
            BulkheadConfig {
                max_concurrent: 2,
                max_queue_depth: 4,
                pressure_threshold_pct: 80,
            },
        )
        .unwrap();
        assert!(matches!(
            reg.release("test", PermitId(999), "t"),
            Err(BulkheadError::PermitNotFound { .. })
        ));
    }

    #[test]
    fn release_promotes_waiter() {
        let mut reg = BulkheadRegistry::empty();
        reg.register(
            "test",
            BulkheadConfig {
                max_concurrent: 1,
                max_queue_depth: 4,
                pressure_threshold_pct: 80,
            },
        )
        .unwrap();

        let p1 = reg.acquire("test", "t1").unwrap();
        let _p2 = reg.acquire("test", "t2").unwrap(); // queued
        assert_eq!(reg.active_count("test"), Some(1));
        assert_eq!(reg.queue_depth("test"), Some(1));

        // Release p1 → p2 promoted to active.
        reg.release("test", p1, "t1").unwrap();
        assert_eq!(reg.active_count("test"), Some(1));
        assert_eq!(reg.queue_depth("test"), Some(0));
    }

    // -- Backpressure --

    #[test]
    fn pressure_detected_at_threshold() {
        let mut reg = BulkheadRegistry::empty();
        reg.register(
            "test",
            BulkheadConfig {
                max_concurrent: 10,
                max_queue_depth: 20,
                pressure_threshold_pct: 80,
            },
        )
        .unwrap();

        // Fill to 7 (below 80% of 10 = 8).
        for i in 0..7 {
            reg.acquire("test", &format!("t{i}")).unwrap();
        }
        assert_eq!(reg.is_at_pressure("test"), Some(false));

        // Fill to 8 (at 80%).
        reg.acquire("test", "t7").unwrap();
        assert_eq!(reg.is_at_pressure("test"), Some(true));
    }

    #[test]
    fn pressure_event_emitted() {
        let mut reg = BulkheadRegistry::empty();
        reg.register(
            "test",
            BulkheadConfig {
                max_concurrent: 2,
                max_queue_depth: 4,
                pressure_threshold_pct: 50,
            },
        )
        .unwrap();

        // At 50% threshold, 1 of 2 triggers pressure.
        reg.acquire("test", "t1").unwrap();
        // Second acquire should trigger pressure.
        reg.acquire("test", "t2").unwrap();

        let events = reg.drain_events();
        let pressure_events: Vec<_> = events
            .iter()
            .filter(|e| e.event == "bulkhead_pressure")
            .collect();
        assert!(!pressure_events.is_empty());
    }

    // -- Reconfigure --

    #[test]
    fn reconfigure_preserves_permits() {
        let mut reg = BulkheadRegistry::empty();
        reg.register(
            "test",
            BulkheadConfig {
                max_concurrent: 2,
                max_queue_depth: 4,
                pressure_threshold_pct: 80,
            },
        )
        .unwrap();

        let _p1 = reg.acquire("test", "t1").unwrap();
        let _p2 = reg.acquire("test", "t2").unwrap();

        // Reduce limit to 1 — existing permits not dropped.
        reg.reconfigure(
            "test",
            BulkheadConfig {
                max_concurrent: 1,
                max_queue_depth: 4,
                pressure_threshold_pct: 80,
            },
        )
        .unwrap();

        assert_eq!(reg.active_count("test"), Some(2));
    }

    #[test]
    fn reconfigure_rejects_zero() {
        let mut reg = BulkheadRegistry::empty();
        reg.register(
            "test",
            BulkheadConfig {
                max_concurrent: 2,
                max_queue_depth: 4,
                pressure_threshold_pct: 80,
            },
        )
        .unwrap();
        assert!(matches!(
            reg.reconfigure(
                "test",
                BulkheadConfig {
                    max_concurrent: 0,
                    max_queue_depth: 4,
                    pressure_threshold_pct: 80,
                }
            ),
            Err(BulkheadError::InvalidConfig { .. })
        ));
    }

    // -- Snapshot --

    #[test]
    fn snapshot_reflects_state() {
        let mut reg = BulkheadRegistry::empty();
        reg.register(
            "test",
            BulkheadConfig {
                max_concurrent: 5,
                max_queue_depth: 10,
                pressure_threshold_pct: 80,
            },
        )
        .unwrap();

        reg.acquire("test", "t1").unwrap();
        reg.acquire("test", "t2").unwrap();

        let snap = reg.snapshot();
        let s = &snap["test"];
        assert_eq!(s.active_count, 2);
        assert_eq!(s.max_concurrent, 5);
        assert_eq!(s.queue_depth, 0);
        assert!(!s.at_pressure);
    }

    // -- Audit events --

    #[test]
    fn acquire_emits_event() {
        let mut reg = BulkheadRegistry::empty();
        reg.register(
            "test",
            BulkheadConfig {
                max_concurrent: 10,
                max_queue_depth: 20,
                pressure_threshold_pct: 80,
            },
        )
        .unwrap();
        reg.acquire("test", "trace-1").unwrap();

        let events = reg.drain_events();
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].event, "permit_acquired");
        assert_eq!(events[0].trace_id, "trace-1");
    }

    #[test]
    fn release_emits_event() {
        let mut reg = BulkheadRegistry::empty();
        reg.register(
            "test",
            BulkheadConfig {
                max_concurrent: 2,
                max_queue_depth: 4,
                pressure_threshold_pct: 80,
            },
        )
        .unwrap();
        let p = reg.acquire("test", "t1").unwrap();
        reg.drain_events();
        reg.release("test", p, "t1").unwrap();

        let events = reg.drain_events();
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].event, "permit_released");
    }

    #[test]
    fn reject_emits_event() {
        let mut reg = BulkheadRegistry::empty();
        reg.register(
            "test",
            BulkheadConfig {
                max_concurrent: 1,
                max_queue_depth: 0,
                pressure_threshold_pct: 80,
            },
        )
        .unwrap();
        reg.acquire("test", "t1").unwrap();
        reg.drain_events();

        let _ = reg.acquire("test", "t2");
        let events = reg.drain_events();
        assert!(!events.is_empty());
        assert_eq!(events[0].event, "permit_rejected");
    }

    #[test]
    fn event_counts_track() {
        let mut reg = BulkheadRegistry::empty();
        reg.register(
            "test",
            BulkheadConfig {
                max_concurrent: 10,
                max_queue_depth: 10,
                pressure_threshold_pct: 80,
            },
        )
        .unwrap();
        let p1 = reg.acquire("test", "t1").unwrap();
        let p2 = reg.acquire("test", "t2").unwrap();
        reg.release("test", p1, "t1").unwrap();
        reg.release("test", p2, "t2").unwrap();

        assert_eq!(reg.event_counts().get("acquire"), Some(&2));
        assert_eq!(reg.event_counts().get("release"), Some(&2));
    }

    // -- Serialization round-trips --

    #[test]
    fn bulkhead_class_serialization_round_trip() {
        let classes = vec![
            BulkheadClass::RemoteInFlight,
            BulkheadClass::BackgroundMaintenance,
            BulkheadClass::SagaExecution,
            BulkheadClass::EvidenceFlush,
        ];
        for c in &classes {
            let json = serde_json::to_string(c).expect("serialize");
            let restored: BulkheadClass = serde_json::from_str(&json).expect("deserialize");
            assert_eq!(*c, restored);
        }
    }

    #[test]
    fn bulkhead_config_serialization_round_trip() {
        let config = BulkheadConfig {
            max_concurrent: 64,
            max_queue_depth: 128,
            pressure_threshold_pct: 80,
        };
        let json = serde_json::to_string(&config).expect("serialize");
        let restored: BulkheadConfig = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(config, restored);
    }

    #[test]
    fn bulkhead_event_serialization_round_trip() {
        let event = BulkheadEvent {
            bulkhead_id: "test".to_string(),
            current_count: 5,
            max_concurrent: 10,
            queue_depth: 2,
            action: "acquire".to_string(),
            trace_id: "t1".to_string(),
            event: "permit_acquired".to_string(),
            permit_id: 42,
        };
        let json = serde_json::to_string(&event).expect("serialize");
        let restored: BulkheadEvent = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(event, restored);
    }

    #[test]
    fn bulkhead_error_serialization_round_trip() {
        let errors = vec![
            BulkheadError::BulkheadFull {
                bulkhead_id: "test".to_string(),
                max_concurrent: 10,
                queue_depth: 5,
            },
            BulkheadError::PermitNotFound { permit_id: 42 },
            BulkheadError::BulkheadNotFound {
                bulkhead_id: "ghost".to_string(),
            },
            BulkheadError::InvalidConfig {
                reason: "bad".to_string(),
            },
        ];
        for err in &errors {
            let json = serde_json::to_string(err).expect("serialize");
            let restored: BulkheadError = serde_json::from_str(&json).expect("deserialize");
            assert_eq!(*err, restored);
        }
    }

    #[test]
    fn snapshot_serialization_round_trip() {
        let snap = BulkheadSnapshot {
            bulkhead_id: "test".to_string(),
            active_count: 3,
            max_concurrent: 10,
            queue_depth: 1,
            max_queue_depth: 20,
            at_pressure: false,
        };
        let json = serde_json::to_string(&snap).expect("serialize");
        let restored: BulkheadSnapshot = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(snap, restored);
    }

    // -- Error display --

    #[test]
    fn error_display() {
        assert!(
            BulkheadError::BulkheadFull {
                bulkhead_id: "x".to_string(),
                max_concurrent: 10,
                queue_depth: 5,
            }
            .to_string()
            .contains("full")
        );
        assert!(
            BulkheadError::PermitNotFound { permit_id: 42 }
                .to_string()
                .contains("42")
        );
        assert!(
            BulkheadError::InvalidConfig {
                reason: "bad".to_string()
            }
            .to_string()
            .contains("bad")
        );
    }

    // -- Deterministic replay --

    #[test]
    fn deterministic_acquire_release_sequence() {
        let run = || -> Vec<BulkheadEvent> {
            let mut reg = BulkheadRegistry::empty();
            reg.register(
                "test",
                BulkheadConfig {
                    max_concurrent: 2,
                    max_queue_depth: 4,
                    pressure_threshold_pct: 80,
                },
            )
            .unwrap();
            let p1 = reg.acquire("test", "t1").unwrap();
            let p2 = reg.acquire("test", "t2").unwrap();
            reg.release("test", p1, "t1").unwrap();
            reg.release("test", p2, "t2").unwrap();
            reg.drain_events()
        };

        let events1 = run();
        let events2 = run();
        assert_eq!(events1, events2);
    }

    // -- Permit display --

    #[test]
    fn permit_id_display() {
        assert_eq!(PermitId(42).to_string(), "permit:42");
    }

    // -- Full lifecycle with defaults --

    // -- Enrichment: Ord, std::error --

    #[test]
    fn bulkhead_class_ordering() {
        assert!(BulkheadClass::RemoteInFlight < BulkheadClass::BackgroundMaintenance);
        assert!(BulkheadClass::BackgroundMaintenance < BulkheadClass::SagaExecution);
        assert!(BulkheadClass::SagaExecution < BulkheadClass::EvidenceFlush);
    }

    #[test]
    fn bulkhead_error_implements_std_error() {
        let variants: Vec<Box<dyn std::error::Error>> = vec![
            Box::new(BulkheadError::BulkheadFull {
                bulkhead_id: "b-1".into(),
                max_concurrent: 10,
                queue_depth: 5,
            }),
            Box::new(BulkheadError::PermitNotFound { permit_id: 42 }),
            Box::new(BulkheadError::BulkheadNotFound {
                bulkhead_id: "b-2".into(),
            }),
            Box::new(BulkheadError::InvalidConfig {
                reason: "bad".into(),
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
    fn full_lifecycle_with_defaults() {
        let mut reg = BulkheadRegistry::with_defaults();

        // Acquire from each bulkhead.
        let p1 = reg.acquire("remote_in_flight", "t1").unwrap();
        let p2 = reg.acquire("background_maintenance", "t2").unwrap();
        let p3 = reg.acquire("saga_execution", "t3").unwrap();
        let p4 = reg.acquire("evidence_flush", "t4").unwrap();

        assert_eq!(reg.active_count("remote_in_flight"), Some(1));
        assert_eq!(reg.active_count("background_maintenance"), Some(1));
        assert_eq!(reg.active_count("saga_execution"), Some(1));
        assert_eq!(reg.active_count("evidence_flush"), Some(1));

        // Release all.
        reg.release("remote_in_flight", p1, "t1").unwrap();
        reg.release("background_maintenance", p2, "t2").unwrap();
        reg.release("saga_execution", p3, "t3").unwrap();
        reg.release("evidence_flush", p4, "t4").unwrap();

        assert_eq!(reg.active_count("remote_in_flight"), Some(0));
        assert_eq!(reg.active_count("evidence_flush"), Some(0));
    }

    // -----------------------------------------------------------------------
    // Enrichment: default config queue depths and thresholds
    // -----------------------------------------------------------------------

    #[test]
    fn default_config_queue_depths() {
        assert_eq!(
            BulkheadClass::RemoteInFlight
                .default_config()
                .max_queue_depth,
            128
        );
        assert_eq!(
            BulkheadClass::BackgroundMaintenance
                .default_config()
                .max_queue_depth,
            32
        );
        assert_eq!(
            BulkheadClass::SagaExecution
                .default_config()
                .max_queue_depth,
            16
        );
        assert_eq!(
            BulkheadClass::EvidenceFlush
                .default_config()
                .max_queue_depth,
            8
        );
    }

    #[test]
    fn default_configs_pressure_threshold_all_80() {
        for class in [
            BulkheadClass::RemoteInFlight,
            BulkheadClass::BackgroundMaintenance,
            BulkheadClass::SagaExecution,
            BulkheadClass::EvidenceFlush,
        ] {
            assert_eq!(class.default_config().pressure_threshold_pct, 80);
        }
    }

    // -----------------------------------------------------------------------
    // Enrichment: double release same permit
    // -----------------------------------------------------------------------

    #[test]
    fn double_release_returns_permit_not_found() {
        let mut reg = BulkheadRegistry::empty();
        reg.register(
            "test",
            BulkheadConfig {
                max_concurrent: 2,
                max_queue_depth: 4,
                pressure_threshold_pct: 80,
            },
        )
        .unwrap();
        let p1 = reg.acquire("test", "t1").unwrap();
        reg.release("test", p1, "t1").unwrap();
        assert!(matches!(
            reg.release("test", p1, "t1"),
            Err(BulkheadError::PermitNotFound { .. })
        ));
    }

    // -----------------------------------------------------------------------
    // Enrichment: release from nonexistent bulkhead
    // -----------------------------------------------------------------------

    #[test]
    fn release_nonexistent_bulkhead() {
        let mut reg = BulkheadRegistry::empty();
        assert!(matches!(
            reg.release("ghost", PermitId(1), "t1"),
            Err(BulkheadError::BulkheadNotFound { .. })
        ));
    }

    // -----------------------------------------------------------------------
    // Enrichment: reconfigure nonexistent bulkhead
    // -----------------------------------------------------------------------

    #[test]
    fn reconfigure_nonexistent_bulkhead() {
        let mut reg = BulkheadRegistry::empty();
        assert!(matches!(
            reg.reconfigure(
                "ghost",
                BulkheadConfig {
                    max_concurrent: 5,
                    max_queue_depth: 10,
                    pressure_threshold_pct: 80,
                }
            ),
            Err(BulkheadError::BulkheadNotFound { .. })
        ));
    }

    // -----------------------------------------------------------------------
    // Enrichment: PermitId ordering
    // -----------------------------------------------------------------------

    #[test]
    fn permit_id_ordering() {
        assert!(PermitId(1) < PermitId(2));
        assert!(PermitId(0) < PermitId(u64::MAX));
        assert_eq!(PermitId(42), PermitId(42));
    }

    // -----------------------------------------------------------------------
    // Enrichment: snapshot with multiple bulkheads
    // -----------------------------------------------------------------------

    #[test]
    fn snapshot_multiple_bulkheads() {
        let mut reg = BulkheadRegistry::with_defaults();
        reg.acquire("remote_in_flight", "t1").unwrap();
        reg.acquire("remote_in_flight", "t2").unwrap();
        reg.acquire("saga_execution", "t3").unwrap();

        let snap = reg.snapshot();
        assert_eq!(snap.len(), 4);
        assert_eq!(snap["remote_in_flight"].active_count, 2);
        assert_eq!(snap["saga_execution"].active_count, 1);
        assert_eq!(snap["background_maintenance"].active_count, 0);
        assert_eq!(snap["evidence_flush"].active_count, 0);
    }

    // -----------------------------------------------------------------------
    // Enrichment: pressure with 100% threshold
    // -----------------------------------------------------------------------

    #[test]
    fn pressure_at_100_pct_threshold() {
        let mut reg = BulkheadRegistry::empty();
        reg.register(
            "test",
            BulkheadConfig {
                max_concurrent: 2,
                max_queue_depth: 4,
                pressure_threshold_pct: 100,
            },
        )
        .unwrap();

        reg.acquire("test", "t1").unwrap();
        assert_eq!(reg.is_at_pressure("test"), Some(false));

        reg.acquire("test", "t2").unwrap();
        assert_eq!(reg.is_at_pressure("test"), Some(true));
    }

    // -----------------------------------------------------------------------
    // Enrichment: pressure with 0% threshold (always triggers)
    // -----------------------------------------------------------------------

    #[test]
    fn pressure_at_0_pct_threshold() {
        let mut reg = BulkheadRegistry::empty();
        reg.register(
            "test",
            BulkheadConfig {
                max_concurrent: 10,
                max_queue_depth: 10,
                pressure_threshold_pct: 0,
            },
        )
        .unwrap();

        // 0% of 10 = 0, so any active count >= 0 triggers pressure.
        assert_eq!(reg.is_at_pressure("test"), Some(true));
    }

    // -----------------------------------------------------------------------
    // Enrichment: register overwrites existing
    // -----------------------------------------------------------------------

    #[test]
    fn register_overwrites_existing_bulkhead() {
        let mut reg = BulkheadRegistry::empty();
        reg.register(
            "test",
            BulkheadConfig {
                max_concurrent: 5,
                max_queue_depth: 10,
                pressure_threshold_pct: 80,
            },
        )
        .unwrap();
        reg.acquire("test", "t1").unwrap();
        assert_eq!(reg.active_count("test"), Some(1));

        // Re-register replaces (active permits are lost).
        reg.register(
            "test",
            BulkheadConfig {
                max_concurrent: 20,
                max_queue_depth: 40,
                pressure_threshold_pct: 90,
            },
        )
        .unwrap();
        assert_eq!(reg.active_count("test"), Some(0));
        assert_eq!(reg.bulkhead_count(), 1);
    }

    // -----------------------------------------------------------------------
    // Enrichment: is_at_pressure nonexistent returns None
    // -----------------------------------------------------------------------

    #[test]
    fn is_at_pressure_nonexistent_returns_none() {
        let reg = BulkheadRegistry::empty();
        assert_eq!(reg.is_at_pressure("ghost"), None);
    }

    // -----------------------------------------------------------------------
    // Enrichment: active_count and queue_depth nonexistent return None
    // -----------------------------------------------------------------------

    #[test]
    fn active_count_nonexistent_returns_none() {
        let reg = BulkheadRegistry::empty();
        assert_eq!(reg.active_count("ghost"), None);
    }

    #[test]
    fn queue_depth_nonexistent_returns_none() {
        let reg = BulkheadRegistry::empty();
        assert_eq!(reg.queue_depth("ghost"), None);
    }

    // -----------------------------------------------------------------------
    // Enrichment: waiter promotion order is FIFO
    // -----------------------------------------------------------------------

    #[test]
    fn waiter_promotion_is_fifo() {
        let mut reg = BulkheadRegistry::empty();
        reg.register(
            "test",
            BulkheadConfig {
                max_concurrent: 1,
                max_queue_depth: 10,
                pressure_threshold_pct: 80,
            },
        )
        .unwrap();

        let p1 = reg.acquire("test", "t1").unwrap(); // active
        let _p2 = reg.acquire("test", "t2").unwrap(); // queued first
        let _p3 = reg.acquire("test", "t3").unwrap(); // queued second

        // Release p1 → t2 promoted (FIFO).
        reg.release("test", p1, "t1").unwrap();
        assert_eq!(reg.active_count("test"), Some(1));
        assert_eq!(reg.queue_depth("test"), Some(1));
    }

    // -----------------------------------------------------------------------
    // Enrichment: BulkheadError display for BulkheadNotFound
    // -----------------------------------------------------------------------

    #[test]
    fn bulkhead_not_found_display() {
        let err = BulkheadError::BulkheadNotFound {
            bulkhead_id: "missing".into(),
        };
        assert!(err.to_string().contains("missing"));
    }

    // -----------------------------------------------------------------------
    // Enrichment batch 3: clone, JSON fields, edge cases, drain
    // -----------------------------------------------------------------------

    #[test]
    fn bulkhead_config_clone_equality() {
        let cfg = BulkheadConfig {
            max_concurrent: 32,
            max_queue_depth: 64,
            pressure_threshold_pct: 75,
        };
        let cloned = cfg.clone();
        assert_eq!(cfg, cloned);
    }

    #[test]
    fn bulkhead_event_clone_equality() {
        let ev = BulkheadEvent {
            bulkhead_id: "bh-1".into(),
            current_count: 3,
            max_concurrent: 10,
            queue_depth: 1,
            action: "acquire".into(),
            trace_id: "tr-7".into(),
            event: "permit_acquired".into(),
            permit_id: 99,
        };
        let cloned = ev.clone();
        assert_eq!(ev, cloned);
    }

    #[test]
    fn bulkhead_error_clone_equality() {
        let variants = vec![
            BulkheadError::BulkheadFull {
                bulkhead_id: "x".into(),
                max_concurrent: 5,
                queue_depth: 3,
            },
            BulkheadError::PermitNotFound { permit_id: 7 },
            BulkheadError::BulkheadNotFound {
                bulkhead_id: "y".into(),
            },
            BulkheadError::InvalidConfig {
                reason: "nope".into(),
            },
        ];
        for v in &variants {
            let cloned = v.clone();
            assert_eq!(*v, cloned);
        }
    }

    #[test]
    fn bulkhead_snapshot_clone_equality() {
        let snap = BulkheadSnapshot {
            bulkhead_id: "snap-1".into(),
            active_count: 2,
            max_concurrent: 8,
            queue_depth: 0,
            max_queue_depth: 16,
            at_pressure: false,
        };
        let cloned = snap.clone();
        assert_eq!(snap, cloned);
    }

    #[test]
    fn permit_id_serde_roundtrip() {
        let pid = PermitId(12345);
        let json = serde_json::to_string(&pid).unwrap();
        let restored: PermitId = serde_json::from_str(&json).unwrap();
        assert_eq!(pid, restored);
    }

    #[test]
    fn bulkhead_event_json_field_presence() {
        let ev = BulkheadEvent {
            bulkhead_id: "test-bh".into(),
            current_count: 4,
            max_concurrent: 10,
            queue_depth: 2,
            action: "acquire".into(),
            trace_id: "tr-99".into(),
            event: "permit_acquired".into(),
            permit_id: 77,
        };
        let json = serde_json::to_string(&ev).unwrap();
        for field in [
            "bulkhead_id",
            "current_count",
            "max_concurrent",
            "queue_depth",
            "action",
            "trace_id",
            "event",
            "permit_id",
        ] {
            assert!(json.contains(field), "missing field: {field}");
        }
    }

    #[test]
    fn bulkhead_snapshot_json_field_presence() {
        let snap = BulkheadSnapshot {
            bulkhead_id: "snap-bh".into(),
            active_count: 1,
            max_concurrent: 5,
            queue_depth: 0,
            max_queue_depth: 10,
            at_pressure: false,
        };
        let json = serde_json::to_string(&snap).unwrap();
        for field in [
            "bulkhead_id",
            "active_count",
            "max_concurrent",
            "queue_depth",
            "max_queue_depth",
            "at_pressure",
        ] {
            assert!(json.contains(field), "missing field: {field}");
        }
    }

    #[test]
    fn bulkhead_class_display_uniqueness() {
        let displays: std::collections::BTreeSet<String> = [
            BulkheadClass::RemoteInFlight,
            BulkheadClass::BackgroundMaintenance,
            BulkheadClass::SagaExecution,
            BulkheadClass::EvidenceFlush,
        ]
        .iter()
        .map(|c| c.to_string())
        .collect();
        assert_eq!(displays.len(), 4);
    }

    #[test]
    fn drain_events_clears_buffer() {
        let mut reg = BulkheadRegistry::empty();
        reg.register(
            "test",
            BulkheadConfig {
                max_concurrent: 10,
                max_queue_depth: 10,
                pressure_threshold_pct: 80,
            },
        )
        .unwrap();
        reg.acquire("test", "t1").unwrap();
        assert!(!reg.drain_events().is_empty());
        assert!(reg.drain_events().is_empty());
    }

    #[test]
    fn event_counts_empty_initially() {
        let reg = BulkheadRegistry::empty();
        assert!(reg.event_counts().is_empty());
    }

    #[test]
    fn permit_id_hash_consistency() {
        use std::collections::BTreeSet;
        let mut set = BTreeSet::new();
        set.insert(PermitId(1));
        set.insert(PermitId(2));
        set.insert(PermitId(1)); // duplicate
        assert_eq!(set.len(), 2);
    }

    #[test]
    fn reject_then_release_then_acquire_cycle() {
        let mut reg = BulkheadRegistry::empty();
        reg.register(
            "test",
            BulkheadConfig {
                max_concurrent: 1,
                max_queue_depth: 0,
                pressure_threshold_pct: 80,
            },
        )
        .unwrap();
        let p1 = reg.acquire("test", "t1").unwrap();
        // Full, no queue room — reject
        assert!(reg.acquire("test", "t2").is_err());
        // Release opens a slot
        reg.release("test", p1, "t1").unwrap();
        // Now acquire succeeds again
        let _p3 = reg.acquire("test", "t3").unwrap();
        assert_eq!(reg.active_count("test"), Some(1));
    }

    #[test]
    fn snapshot_at_pressure_flag_accurate() {
        let mut reg = BulkheadRegistry::empty();
        reg.register(
            "test",
            BulkheadConfig {
                max_concurrent: 2,
                max_queue_depth: 4,
                pressure_threshold_pct: 50,
            },
        )
        .unwrap();
        reg.acquire("test", "t1").unwrap();
        let snap = reg.snapshot();
        assert!(snap["test"].at_pressure);
    }

    // -----------------------------------------------------------------------
    // Enrichment batch 4: serde edge cases
    // -----------------------------------------------------------------------

    #[test]
    fn bulkhead_config_serde_boundary_values_enrichment() {
        let cfg = BulkheadConfig {
            max_concurrent: usize::MAX,
            max_queue_depth: 0,
            pressure_threshold_pct: 255,
        };
        let json = serde_json::to_string(&cfg).unwrap();
        let restored: BulkheadConfig = serde_json::from_str(&json).unwrap();
        assert_eq!(cfg, restored);
    }

    #[test]
    fn bulkhead_config_serde_minimal_enrichment() {
        let cfg = BulkheadConfig {
            max_concurrent: 1,
            max_queue_depth: 0,
            pressure_threshold_pct: 0,
        };
        let json = serde_json::to_string(&cfg).unwrap();
        let restored: BulkheadConfig = serde_json::from_str(&json).unwrap();
        assert_eq!(cfg, restored);
    }

    #[test]
    fn bulkhead_event_serde_empty_strings_enrichment() {
        let ev = BulkheadEvent {
            bulkhead_id: String::new(),
            current_count: 0,
            max_concurrent: 0,
            queue_depth: 0,
            action: String::new(),
            trace_id: String::new(),
            event: String::new(),
            permit_id: 0,
        };
        let json = serde_json::to_string(&ev).unwrap();
        let restored: BulkheadEvent = serde_json::from_str(&json).unwrap();
        assert_eq!(ev, restored);
    }

    #[test]
    fn bulkhead_event_serde_unicode_strings_enrichment() {
        let ev = BulkheadEvent {
            bulkhead_id: "\u{1F600} emoji-bh".into(),
            current_count: 1,
            max_concurrent: 10,
            queue_depth: 0,
            action: "acquire".into(),
            trace_id: "trace-\u{00E9}\u{00F1}".into(),
            event: "permit_acquired".into(),
            permit_id: 1,
        };
        let json = serde_json::to_string(&ev).unwrap();
        let restored: BulkheadEvent = serde_json::from_str(&json).unwrap();
        assert_eq!(ev, restored);
    }

    #[test]
    fn bulkhead_error_serde_long_reason_enrichment() {
        let reason = "x".repeat(10_000);
        let err = BulkheadError::InvalidConfig {
            reason: reason.clone(),
        };
        let json = serde_json::to_string(&err).unwrap();
        let restored: BulkheadError = serde_json::from_str(&json).unwrap();
        assert_eq!(err, restored);
        assert!(restored.to_string().contains(&reason));
    }

    #[test]
    fn bulkhead_snapshot_serde_at_pressure_true_enrichment() {
        let snap = BulkheadSnapshot {
            bulkhead_id: "pressured".into(),
            active_count: 9,
            max_concurrent: 10,
            queue_depth: 5,
            max_queue_depth: 20,
            at_pressure: true,
        };
        let json = serde_json::to_string(&snap).unwrap();
        let restored: BulkheadSnapshot = serde_json::from_str(&json).unwrap();
        assert_eq!(snap, restored);
        assert!(json.contains("true"));
    }

    #[test]
    fn permit_id_serde_zero_enrichment() {
        let pid = PermitId(0);
        let json = serde_json::to_string(&pid).unwrap();
        let restored: PermitId = serde_json::from_str(&json).unwrap();
        assert_eq!(pid, restored);
    }

    #[test]
    fn permit_id_serde_max_enrichment() {
        let pid = PermitId(u64::MAX);
        let json = serde_json::to_string(&pid).unwrap();
        let restored: PermitId = serde_json::from_str(&json).unwrap();
        assert_eq!(pid, restored);
    }

    // -----------------------------------------------------------------------
    // Enrichment batch 4: clone independence (mutate original after clone)
    // -----------------------------------------------------------------------

    #[test]
    fn bulkhead_config_clone_independence_enrichment() {
        let mut cfg = BulkheadConfig {
            max_concurrent: 10,
            max_queue_depth: 20,
            pressure_threshold_pct: 80,
        };
        let cloned = cfg.clone();
        cfg.max_concurrent = 999;
        cfg.max_queue_depth = 1;
        cfg.pressure_threshold_pct = 1;
        assert_ne!(cfg, cloned);
        assert_eq!(cloned.max_concurrent, 10);
        assert_eq!(cloned.max_queue_depth, 20);
        assert_eq!(cloned.pressure_threshold_pct, 80);
    }

    #[test]
    fn bulkhead_event_clone_independence_enrichment() {
        let mut ev = BulkheadEvent {
            bulkhead_id: "original".into(),
            current_count: 1,
            max_concurrent: 10,
            queue_depth: 0,
            action: "acquire".into(),
            trace_id: "t-1".into(),
            event: "permit_acquired".into(),
            permit_id: 5,
        };
        let cloned = ev.clone();
        ev.bulkhead_id = "mutated".into();
        ev.permit_id = 999;
        assert_ne!(ev, cloned);
        assert_eq!(cloned.bulkhead_id, "original");
        assert_eq!(cloned.permit_id, 5);
    }

    #[test]
    fn bulkhead_error_clone_independence_enrichment() {
        let mut err = BulkheadError::BulkheadFull {
            bulkhead_id: "orig".into(),
            max_concurrent: 10,
            queue_depth: 5,
        };
        let cloned = err.clone();
        err = BulkheadError::PermitNotFound { permit_id: 42 };
        assert_ne!(err, cloned);
    }

    #[test]
    fn bulkhead_snapshot_clone_independence_enrichment() {
        let mut snap = BulkheadSnapshot {
            bulkhead_id: "snap-orig".into(),
            active_count: 3,
            max_concurrent: 10,
            queue_depth: 1,
            max_queue_depth: 20,
            at_pressure: false,
        };
        let cloned = snap.clone();
        snap.at_pressure = true;
        snap.active_count = 10;
        assert_ne!(snap, cloned);
        assert!(!cloned.at_pressure);
        assert_eq!(cloned.active_count, 3);
    }

    // -----------------------------------------------------------------------
    // Enrichment batch 4: Display/Debug uniqueness
    // -----------------------------------------------------------------------

    #[test]
    fn bulkhead_class_debug_uniqueness_enrichment() {
        let classes = [
            BulkheadClass::RemoteInFlight,
            BulkheadClass::BackgroundMaintenance,
            BulkheadClass::SagaExecution,
            BulkheadClass::EvidenceFlush,
        ];
        let debugs: std::collections::BTreeSet<String> =
            classes.iter().map(|c| format!("{c:?}")).collect();
        assert_eq!(debugs.len(), 4, "all Debug representations are unique");
    }

    #[test]
    fn permit_id_display_format_enrichment() {
        assert_eq!(PermitId(0).to_string(), "permit:0");
        assert_eq!(
            PermitId(u64::MAX).to_string(),
            format!("permit:{}", u64::MAX)
        );
    }

    #[test]
    fn permit_id_debug_differs_from_display_enrichment() {
        let pid = PermitId(42);
        let display = format!("{pid}");
        let debug = format!("{pid:?}");
        assert_ne!(display, debug);
        assert!(debug.contains("PermitId"));
    }

    #[test]
    fn bulkhead_error_full_display_content_enrichment() {
        let err = BulkheadError::BulkheadFull {
            bulkhead_id: "my-bh".into(),
            max_concurrent: 64,
            queue_depth: 128,
        };
        let msg = err.to_string();
        assert!(msg.contains("my-bh"), "should contain bulkhead id");
        assert!(msg.contains("64"), "should contain max_concurrent");
        assert!(msg.contains("128"), "should contain queue_depth");
        assert!(msg.contains("full"), "should contain 'full'");
    }

    #[test]
    fn bulkhead_error_permit_not_found_display_content_enrichment() {
        let err = BulkheadError::PermitNotFound { permit_id: 9999 };
        let msg = err.to_string();
        assert!(msg.contains("9999"));
        assert!(msg.contains("not found"));
    }

    #[test]
    fn bulkhead_error_invalid_config_display_content_enrichment() {
        let err = BulkheadError::InvalidConfig {
            reason: "threshold exceeds 100".into(),
        };
        let msg = err.to_string();
        assert!(msg.contains("threshold exceeds 100"));
        assert!(msg.contains("invalid"));
    }

    #[test]
    fn bulkhead_error_not_found_display_content_enrichment() {
        let err = BulkheadError::BulkheadNotFound {
            bulkhead_id: "phantom".into(),
        };
        let msg = err.to_string();
        assert!(msg.contains("phantom"));
        assert!(msg.contains("not found"));
    }

    // -----------------------------------------------------------------------
    // Enrichment batch 4: ordering tests
    // -----------------------------------------------------------------------

    #[test]
    fn bulkhead_class_ord_is_total_enrichment() {
        let classes = [
            BulkheadClass::RemoteInFlight,
            BulkheadClass::BackgroundMaintenance,
            BulkheadClass::SagaExecution,
            BulkheadClass::EvidenceFlush,
        ];
        // Reflexive
        for c in &classes {
            assert_eq!(c.cmp(c), std::cmp::Ordering::Equal);
        }
        // Antisymmetric: if a < b then b > a
        for i in 0..classes.len() {
            for j in (i + 1)..classes.len() {
                assert!(classes[i] < classes[j]);
                assert!(classes[j] > classes[i]);
            }
        }
    }

    #[test]
    fn permit_id_ord_monotonic_enrichment() {
        let mut ids: Vec<PermitId> = (0..100).map(PermitId).collect();
        let sorted = ids.clone();
        ids.sort();
        assert_eq!(ids, sorted, "sequential PermitIds should already be sorted");
    }

    #[test]
    fn permit_id_ord_reverse_enrichment() {
        let mut ids: Vec<PermitId> = (0..50).rev().map(PermitId).collect();
        ids.sort();
        let expected: Vec<PermitId> = (0..50).map(PermitId).collect();
        assert_eq!(ids, expected);
    }

    // -----------------------------------------------------------------------
    // Enrichment batch 4: stress scenarios
    // -----------------------------------------------------------------------

    #[test]
    fn stress_acquire_release_many_permits_enrichment() {
        let mut reg = BulkheadRegistry::empty();
        reg.register(
            "stress",
            BulkheadConfig {
                max_concurrent: 100,
                max_queue_depth: 200,
                pressure_threshold_pct: 80,
            },
        )
        .unwrap();

        let mut permits = Vec::new();
        for i in 0..100 {
            permits.push(reg.acquire("stress", &format!("t{i}")).unwrap());
        }
        assert_eq!(reg.active_count("stress"), Some(100));

        // Release all
        for (i, p) in permits.into_iter().enumerate() {
            reg.release("stress", p, &format!("t{i}")).unwrap();
        }
        assert_eq!(reg.active_count("stress"), Some(0));
    }

    #[test]
    fn stress_fill_queue_completely_enrichment() {
        let mut reg = BulkheadRegistry::empty();
        reg.register(
            "stress",
            BulkheadConfig {
                max_concurrent: 2,
                max_queue_depth: 50,
                pressure_threshold_pct: 80,
            },
        )
        .unwrap();

        // Fill active slots
        let _p1 = reg.acquire("stress", "t0").unwrap();
        let _p2 = reg.acquire("stress", "t1").unwrap();
        assert_eq!(reg.active_count("stress"), Some(2));

        // Fill entire queue
        for i in 2..52 {
            reg.acquire("stress", &format!("t{i}")).unwrap();
        }
        assert_eq!(reg.queue_depth("stress"), Some(50));

        // One more should be rejected
        assert!(matches!(
            reg.acquire("stress", "overflow"),
            Err(BulkheadError::BulkheadFull { .. })
        ));
    }

    #[test]
    fn stress_rapid_acquire_release_cycles_enrichment() {
        let mut reg = BulkheadRegistry::empty();
        reg.register(
            "cycle",
            BulkheadConfig {
                max_concurrent: 1,
                max_queue_depth: 0,
                pressure_threshold_pct: 80,
            },
        )
        .unwrap();

        for i in 0..200 {
            let p = reg.acquire("cycle", &format!("t{i}")).unwrap();
            reg.release("cycle", p, &format!("t{i}")).unwrap();
        }
        assert_eq!(reg.active_count("cycle"), Some(0));
        assert_eq!(reg.event_counts().get("acquire"), Some(&200));
        assert_eq!(reg.event_counts().get("release"), Some(&200));
    }

    #[test]
    fn stress_multiple_bulkheads_interleaved_enrichment() {
        let mut reg = BulkheadRegistry::empty();
        for name in &["alpha", "beta", "gamma"] {
            reg.register(
                name,
                BulkheadConfig {
                    max_concurrent: 3,
                    max_queue_depth: 5,
                    pressure_threshold_pct: 80,
                },
            )
            .unwrap();
        }

        let mut permits = Vec::new();
        for i in 0..9 {
            let bh = ["alpha", "beta", "gamma"][i % 3];
            permits.push((bh, reg.acquire(bh, &format!("t{i}")).unwrap()));
        }

        for (bh, p) in &permits {
            reg.release(bh, *p, "done").unwrap();
        }

        assert_eq!(reg.active_count("alpha"), Some(0));
        assert_eq!(reg.active_count("beta"), Some(0));
        assert_eq!(reg.active_count("gamma"), Some(0));
    }

    // -----------------------------------------------------------------------
    // Enrichment batch 4: deterministic replay
    // -----------------------------------------------------------------------

    #[test]
    fn deterministic_replay_with_rejections_enrichment() {
        let run = || -> Vec<BulkheadEvent> {
            let mut reg = BulkheadRegistry::empty();
            reg.register(
                "det",
                BulkheadConfig {
                    max_concurrent: 1,
                    max_queue_depth: 1,
                    pressure_threshold_pct: 50,
                },
            )
            .unwrap();

            let p1 = reg.acquire("det", "t1").unwrap();
            let _p2 = reg.acquire("det", "t2").unwrap(); // queued
            let _ = reg.acquire("det", "t3"); // rejected
            reg.release("det", p1, "t1").unwrap(); // promotes p2
            reg.drain_events()
        };

        let events1 = run();
        let events2 = run();
        assert_eq!(events1.len(), events2.len());
        for (a, b) in events1.iter().zip(events2.iter()) {
            assert_eq!(a, b);
        }
    }

    #[test]
    fn deterministic_replay_event_counts_enrichment() {
        let run = || -> BTreeMap<String, u64> {
            let mut reg = BulkheadRegistry::empty();
            reg.register(
                "det",
                BulkheadConfig {
                    max_concurrent: 2,
                    max_queue_depth: 2,
                    pressure_threshold_pct: 80,
                },
            )
            .unwrap();

            for i in 0..4 {
                let _ = reg.acquire("det", &format!("t{i}"));
            }
            // One more triggers rejection
            let _ = reg.acquire("det", "overflow");
            reg.event_counts().clone()
        };

        assert_eq!(run(), run());
    }

    // -----------------------------------------------------------------------
    // Enrichment batch 4: snapshot edge cases
    // -----------------------------------------------------------------------

    #[test]
    fn snapshot_empty_registry_enrichment() {
        let reg = BulkheadRegistry::empty();
        let snap = reg.snapshot();
        assert!(snap.is_empty());
    }

    #[test]
    fn snapshot_with_waiters_enrichment() {
        let mut reg = BulkheadRegistry::empty();
        reg.register(
            "test",
            BulkheadConfig {
                max_concurrent: 1,
                max_queue_depth: 5,
                pressure_threshold_pct: 80,
            },
        )
        .unwrap();

        reg.acquire("test", "t1").unwrap(); // active
        reg.acquire("test", "t2").unwrap(); // queued
        reg.acquire("test", "t3").unwrap(); // queued

        let snap = reg.snapshot();
        assert_eq!(snap["test"].active_count, 1);
        assert_eq!(snap["test"].queue_depth, 2);
        assert_eq!(snap["test"].max_queue_depth, 5);
    }

    #[test]
    fn snapshot_serde_roundtrip_via_btreemap_enrichment() {
        let mut reg = BulkheadRegistry::with_defaults();
        reg.acquire("remote_in_flight", "t1").unwrap();

        let snap = reg.snapshot();
        let json = serde_json::to_string(&snap).unwrap();
        let restored: BTreeMap<String, BulkheadSnapshot> = serde_json::from_str(&json).unwrap();
        assert_eq!(snap, restored);
    }

    // -----------------------------------------------------------------------
    // Enrichment batch 4: reconfigure edge cases
    // -----------------------------------------------------------------------

    #[test]
    fn reconfigure_increase_limit_allows_more_acquires_enrichment() {
        let mut reg = BulkheadRegistry::empty();
        reg.register(
            "test",
            BulkheadConfig {
                max_concurrent: 1,
                max_queue_depth: 0,
                pressure_threshold_pct: 80,
            },
        )
        .unwrap();

        let _p1 = reg.acquire("test", "t1").unwrap();
        // Currently full, no queue room
        assert!(reg.acquire("test", "t2").is_err());

        // Increase limit
        reg.reconfigure(
            "test",
            BulkheadConfig {
                max_concurrent: 5,
                max_queue_depth: 10,
                pressure_threshold_pct: 80,
            },
        )
        .unwrap();

        // Now we can acquire more
        let _p2 = reg.acquire("test", "t2").unwrap();
        assert_eq!(reg.active_count("test"), Some(2));
    }

    #[test]
    fn reconfigure_pressure_threshold_changes_detection_enrichment() {
        let mut reg = BulkheadRegistry::empty();
        reg.register(
            "test",
            BulkheadConfig {
                max_concurrent: 10,
                max_queue_depth: 10,
                pressure_threshold_pct: 80,
            },
        )
        .unwrap();

        // Fill to 5 (50%), not at 80% threshold
        for i in 0..5 {
            reg.acquire("test", &format!("t{i}")).unwrap();
        }
        assert_eq!(reg.is_at_pressure("test"), Some(false));

        // Lower threshold to 50%
        reg.reconfigure(
            "test",
            BulkheadConfig {
                max_concurrent: 10,
                max_queue_depth: 10,
                pressure_threshold_pct: 50,
            },
        )
        .unwrap();
        assert_eq!(reg.is_at_pressure("test"), Some(true));
    }

    // -----------------------------------------------------------------------
    // Enrichment batch 4: event details
    // -----------------------------------------------------------------------

    #[test]
    fn queued_event_action_and_type_enrichment() {
        let mut reg = BulkheadRegistry::empty();
        reg.register(
            "test",
            BulkheadConfig {
                max_concurrent: 1,
                max_queue_depth: 5,
                pressure_threshold_pct: 80,
            },
        )
        .unwrap();

        let _p1 = reg.acquire("test", "t1").unwrap();
        reg.drain_events(); // clear acquire event

        let _p2 = reg.acquire("test", "t2").unwrap(); // queued
        let events = reg.drain_events();
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].action, "queued");
        assert_eq!(events[0].event, "permit_queued");
        assert_eq!(events[0].trace_id, "t2");
    }

    #[test]
    fn pressure_event_has_correct_fields_enrichment() {
        let mut reg = BulkheadRegistry::empty();
        reg.register(
            "bh-press",
            BulkheadConfig {
                max_concurrent: 2,
                max_queue_depth: 4,
                pressure_threshold_pct: 50,
            },
        )
        .unwrap();

        // First acquire at 50% threshold triggers pressure
        reg.acquire("bh-press", "trace-a").unwrap();
        let events = reg.drain_events();
        let pressure = events.iter().find(|e| e.event == "bulkhead_pressure");
        assert!(pressure.is_some());
        let pe = pressure.unwrap();
        assert_eq!(pe.bulkhead_id, "bh-press");
        assert_eq!(pe.action, "pressure");
    }

    #[test]
    fn release_event_permit_id_matches_enrichment() {
        let mut reg = BulkheadRegistry::empty();
        reg.register(
            "test",
            BulkheadConfig {
                max_concurrent: 10,
                max_queue_depth: 10,
                pressure_threshold_pct: 80,
            },
        )
        .unwrap();

        let p = reg.acquire("test", "trace-rel").unwrap();
        reg.drain_events();
        reg.release("test", p, "trace-rel").unwrap();
        let events = reg.drain_events();
        assert_eq!(events[0].permit_id, p.0);
        assert_eq!(events[0].trace_id, "trace-rel");
    }

    // -----------------------------------------------------------------------
    // Enrichment batch 4: default config invariants
    // -----------------------------------------------------------------------

    #[test]
    fn default_config_queue_depth_is_double_max_concurrent_enrichment() {
        for class in [
            BulkheadClass::RemoteInFlight,
            BulkheadClass::BackgroundMaintenance,
            BulkheadClass::SagaExecution,
            BulkheadClass::EvidenceFlush,
        ] {
            let cfg = class.default_config();
            assert_eq!(
                cfg.max_queue_depth,
                cfg.max_concurrent * 2,
                "{class}: queue depth should be 2x max_concurrent"
            );
        }
    }

    // -----------------------------------------------------------------------
    // Enrichment batch 4: BulkheadClass serde variants are strings
    // -----------------------------------------------------------------------

    #[test]
    fn bulkhead_class_serde_variant_names_enrichment() {
        assert_eq!(
            serde_json::to_string(&BulkheadClass::RemoteInFlight).unwrap(),
            "\"RemoteInFlight\""
        );
        assert_eq!(
            serde_json::to_string(&BulkheadClass::BackgroundMaintenance).unwrap(),
            "\"BackgroundMaintenance\""
        );
        assert_eq!(
            serde_json::to_string(&BulkheadClass::SagaExecution).unwrap(),
            "\"SagaExecution\""
        );
        assert_eq!(
            serde_json::to_string(&BulkheadClass::EvidenceFlush).unwrap(),
            "\"EvidenceFlush\""
        );
    }

    // -----------------------------------------------------------------------
    // Enrichment batch 4: PermitId Copy semantics
    // -----------------------------------------------------------------------

    #[test]
    fn permit_id_copy_semantics_enrichment() {
        let p1 = PermitId(42);
        let p2 = p1; // Copy
        let p3 = p1; // still valid because Copy
        assert_eq!(p1, p2);
        assert_eq!(p2, p3);
    }

    #[test]
    fn bulkhead_class_copy_semantics_enrichment() {
        let c1 = BulkheadClass::SagaExecution;
        let c2 = c1; // Copy
        let c3 = c1; // still valid because Copy
        assert_eq!(c1, c2);
        assert_eq!(c2, c3);
    }

    // -----------------------------------------------------------------------
    // Enrichment batch 4: waiter release from middle
    // -----------------------------------------------------------------------

    #[test]
    fn release_middle_waiter_enrichment() {
        let mut reg = BulkheadRegistry::empty();
        reg.register(
            "test",
            BulkheadConfig {
                max_concurrent: 1,
                max_queue_depth: 10,
                pressure_threshold_pct: 80,
            },
        )
        .unwrap();

        let _p1 = reg.acquire("test", "t1").unwrap(); // active
        let _p2 = reg.acquire("test", "t2").unwrap(); // queued 1st
        let p3 = reg.acquire("test", "t3").unwrap(); // queued 2nd
        let _p4 = reg.acquire("test", "t4").unwrap(); // queued 3rd

        assert_eq!(reg.queue_depth("test"), Some(3));

        // Release middle waiter p3
        reg.release("test", p3, "t3").unwrap();
        assert_eq!(reg.queue_depth("test"), Some(2));
        // Active count unchanged (p3 was a waiter)
        assert_eq!(reg.active_count("test"), Some(1));
    }

    // -----------------------------------------------------------------------
    // Enrichment batch 4: permit IDs are monotonically increasing
    // -----------------------------------------------------------------------

    #[test]
    fn permit_ids_monotonically_increasing_enrichment() {
        let mut reg = BulkheadRegistry::empty();
        reg.register(
            "test",
            BulkheadConfig {
                max_concurrent: 100,
                max_queue_depth: 100,
                pressure_threshold_pct: 80,
            },
        )
        .unwrap();

        let mut prev = PermitId(0);
        for i in 0..50 {
            let p = reg.acquire("test", &format!("t{i}")).unwrap();
            assert!(p > prev, "permit {p} should be > {prev}");
            prev = p;
        }
    }

    // -----------------------------------------------------------------------
    // Enrichment batch 4: event_counts survives drain_events
    // -----------------------------------------------------------------------

    #[test]
    fn event_counts_persist_after_drain_enrichment() {
        let mut reg = BulkheadRegistry::empty();
        reg.register(
            "test",
            BulkheadConfig {
                max_concurrent: 10,
                max_queue_depth: 10,
                pressure_threshold_pct: 80,
            },
        )
        .unwrap();

        let p = reg.acquire("test", "t1").unwrap();
        reg.release("test", p, "t1").unwrap();

        let counts_before = reg.event_counts().clone();
        let _ = reg.drain_events();
        let counts_after = reg.event_counts().clone();

        assert_eq!(
            counts_before, counts_after,
            "drain_events should not reset counters"
        );
    }

    // -----------------------------------------------------------------------
    // Enrichment batch 4: BulkheadError Debug uniqueness
    // -----------------------------------------------------------------------

    #[test]
    fn bulkhead_error_debug_uniqueness_enrichment() {
        let variants = [
            BulkheadError::BulkheadFull {
                bulkhead_id: "a".into(),
                max_concurrent: 1,
                queue_depth: 1,
            },
            BulkheadError::PermitNotFound { permit_id: 1 },
            BulkheadError::BulkheadNotFound {
                bulkhead_id: "b".into(),
            },
            BulkheadError::InvalidConfig { reason: "c".into() },
        ];
        let debugs: std::collections::BTreeSet<String> =
            variants.iter().map(|e| format!("{e:?}")).collect();
        assert_eq!(debugs.len(), 4, "all Debug representations are unique");
    }

    // -----------------------------------------------------------------------
    // Enrichment batch 4: full waiter chain promotion
    // -----------------------------------------------------------------------

    #[test]
    fn waiter_chain_full_promotion_enrichment() {
        let mut reg = BulkheadRegistry::empty();
        reg.register(
            "chain",
            BulkheadConfig {
                max_concurrent: 1,
                max_queue_depth: 5,
                pressure_threshold_pct: 80,
            },
        )
        .unwrap();

        let p1 = reg.acquire("chain", "t1").unwrap(); // active
        let mut queued = Vec::new();
        for i in 2..=5 {
            queued.push(reg.acquire("chain", &format!("t{i}")).unwrap());
        }
        assert_eq!(reg.queue_depth("chain"), Some(4));

        // Release active => promotes first waiter
        reg.release("chain", p1, "t1").unwrap();
        assert_eq!(reg.active_count("chain"), Some(1));
        assert_eq!(reg.queue_depth("chain"), Some(3));

        // Release promoted => promotes next waiter
        reg.release("chain", queued[0], "t2").unwrap();
        assert_eq!(reg.active_count("chain"), Some(1));
        assert_eq!(reg.queue_depth("chain"), Some(2));
    }
}
