//! Shared, non-overcommitting admission for native Wasm linear memory.
//!
//! Each admitted instance reserves its maximum permitted page count until its
//! state is destroyed. This covers future growth without introducing shared
//! availability decisions into guest memory.grow. Binding a pool to a registry
//! is lazy; denied policies/imports and unpolled tasks reserve nothing.
//!
//! A pool is explicitly supplied by the embedder, never a process-global grant.
//! Clones share capacity, NOT guest bytes. Pages are Wasm's 64 KiB logical pages;
//! reservations are not physical allocation or total process-memory accounting.
//! Code, tables, stacks, allocator overhead and trusted providers need their own
//! limits. Admission order is an embedding input, not a replayed host effect.

use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use super::numeric::WasmHostError;
use crate::checkpoint::CancellationToken;

/// Maximum number of partition edges below a root. Bounds both ancestor
/// observation at guest checkpoints and destruction of nested reservations.
pub const WASM_MEMORY_POOL_MAX_DEPTH: usize = 64;

#[derive(Debug)]
struct Pool {
    capacity: u64,
    available: AtomicU64,
    cancellation: CancellationToken,
    depth: usize,
    // Own the parent's capacity, rather than copying an apparent allowance.
    // Live descendant instances keep this reservation alive through their Arc.
    parent: Option<MemoryReservation>,
}

/// A fixed shared linear-memory ceiling. Pass clones to
/// [`super::numeric::WasmHostImports::bind_memory_pool`] on every participating
/// registry. There is no reset, capacity-widening or deserialization operation.
/// An instance retains its reservation after an export traps or is cancelled;
/// unpublished startup/command state releases it when dropped.
#[derive(Debug, Clone)]
pub struct WasmMemoryPool(Arc<Pool>);

impl WasmMemoryPool {
    /// Define a capacity in 64 KiB pages without allocating guest memory.
    /// Zero admits memoryless modules and memories whose effective maximum is
    /// zero. A zero initial size with a positive maximum still needs capacity.
    pub fn new(capacity_pages: u64) -> Self {
        Self(Arc::new(Pool {
            capacity: capacity_pages,
            available: AtomicU64::new(capacity_pages),
            cancellation: CancellationToken::new(),
            depth: 0,
            parent: None,
        }))
    }

    /// Carve out protected capacity for a tenant or execution cell. Partitioning
    /// immediately reserves the child's ENTIRE capacity in this pool, even when
    /// the child has no instances yet. Siblings cannot borrow an idle child's
    /// allotment. Guest admission within the child stays lazy as before.
    ///
    /// The parent reservation is released only when the last child handle and
    /// all child instances/descendants are destroyed. Dropping an operator's
    /// handle cannot refund pages still promised to live guest state. There is
    /// no reparenting, grant duplication or guest-memory sharing. Like new(),
    /// this is an embedding configuration operation, not a guest instruction.
    /// A revoked ancestor cannot create an active descendant. Nesting is
    /// bounded by WASM_MEMORY_POOL_MAX_DEPTH; refusal reserves no capacity.
    pub fn partition(&self, capacity_pages: u64) -> Result<Self, WasmHostError> {
        self.check_active()?;
        if self.0.depth >= WASM_MEMORY_POOL_MAX_DEPTH {
            return Err(WasmHostError::MemoryPoolDepthExceeded {
                max: WASM_MEMORY_POOL_MAX_DEPTH,
            });
        }
        let parent = self.reserve(capacity_pages)?;
        let child = Self(Arc::new(Pool {
            capacity: capacity_pages,
            available: AtomicU64::new(capacity_pages),
            cancellation: CancellationToken::new(),
            depth: self.0.depth + 1,
            parent: Some(parent),
        }));
        child.check_active()?;
        Ok(child)
    }

    /// Permanently revoke admission AND execution for this pool's subtree.
    /// Clones share the request. Ancestors and sibling partitions are untouched.
    /// Participating instances observe it at existing guest, activation, host
    /// and replay checkpoints, including modules without memory or host calls.
    /// No instance enumeration, lock, background worker or task handle is needed.
    ///
    /// Revocation is cooperative, not a native-callback/allocator preemption
    /// guarantee. Work already past a checkpoint can complete before the next
    /// observation. Completed effects and existing terminal faults are retained.
    /// Live memory stays charged until destruction; this never refunds pages,
    /// resets a pool, or widens its authority. Create a new authorized scope to
    /// restart work. A replay transcript cannot revoke a live pool on its own.
    pub fn revoke(&self) {
        self.0.cancellation.cancel();
    }

    /// Observe permanent revocation of this pool or any ancestor. This is not
    /// an execution lease: a concurrent request may follow an active snapshot.
    pub fn is_revoked(&self) -> bool {
        let mut current = self;
        loop {
            if current.0.cancellation.is_cancelled() {
                return true;
            }
            match &current.0.parent {
                Some(parent) => current = &parent.pool,
                None => return false,
            }
        }
    }

    pub(crate) fn check_active(&self) -> Result<(), WasmHostError> {
        if self.is_revoked() {
            Err(WasmHostError::MemoryPoolRevoked)
        } else {
            Ok(())
        }
    }

    pub fn capacity_pages(&self) -> u64 {
        self.0.capacity
    }

    /// Whether this pool holds an allotment from another pool. This exposes no
    /// parent handle with which a tenant could bypass its assigned ceiling.
    pub fn is_partition(&self) -> bool {
        self.0.parent.is_some()
    }

    /// One instantaneous accounting observation, including future growth held
    /// for live instances. Another thread may admit/release immediately after it.
    pub fn reserved_pages(&self) -> u64 {
        self.0.capacity - self.0.available.load(Ordering::Acquire)
    }

    pub fn available_pages(&self) -> u64 {
        self.0.available.load(Ordering::Acquire)
    }

    pub(crate) fn reserve(&self, pages: u64) -> Result<MemoryReservation, WasmHostError> {
        let mut available = self.0.available.load(Ordering::Acquire);
        loop {
            self.check_active()?;
            let remaining =
                available
                    .checked_sub(pages)
                    .ok_or(WasmHostError::MemoryPoolExhausted {
                        requested_pages: pages,
                        available_pages: available,
                    })?;
            match self.0.available.compare_exchange_weak(
                available,
                remaining,
                Ordering::AcqRel,
                Ordering::Acquire,
            ) {
                Ok(_) => {
                    let reservation = MemoryReservation {
                        pool: self.clone(),
                        pages,
                    };
                    // A request racing the reservation cannot leak the charge.
                    // A later request is still observed by execution checkpoints.
                    self.check_active()?;
                    return Ok(reservation);
                }
                Err(actual) => available = actual,
            }
        }
    }
}

/// Not cloneable or serializable: one owner releases exactly one reservation.
/// Kept inside the instance-owned registry, never inside the scheduler queue or
/// transcript observer (both may disappear before the actual instance does).
#[derive(Debug)]
pub(crate) struct MemoryReservation {
    pool: WasmMemoryPool,
    pages: u64,
}

impl MemoryReservation {
    pub(crate) fn pages(&self) -> u64 {
        self.pages
    }
}

impl Drop for MemoryReservation {
    fn drop(&mut self) {
        // Every reservation subtracted these pages once; no other API can add
        // capacity. Releasing cannot exceed the fixed ceiling or wrap u64.
        self.pool
            .0
            .available
            .fetch_add(self.pages, Ordering::Release);
    }
}
