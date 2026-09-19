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

#[derive(Debug)]
struct Pool {
    capacity: u64,
    available: AtomicU64,
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
    pub fn partition(&self, capacity_pages: u64) -> Result<Self, WasmHostError> {
        let parent = self.reserve(capacity_pages)?;
        Ok(Self(Arc::new(Pool {
            capacity: capacity_pages,
            available: AtomicU64::new(capacity_pages),
            parent: Some(parent),
        })))
    }

    pub fn capacity_pages(&self) -> u64 { self.0.capacity }

    /// Whether this pool holds an allotment from another pool. This exposes no
    /// parent handle with which a tenant could bypass its assigned ceiling.
    pub fn is_partition(&self) -> bool { self.0.parent.is_some() }

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
            let remaining = available.checked_sub(pages)
                .ok_or(WasmHostError::MemoryPoolExhausted {
                    requested_pages: pages, available_pages: available,
                })?;
            match self.0.available.compare_exchange_weak(
                available, remaining, Ordering::AcqRel, Ordering::Acquire,
            ) {
                Ok(_) => return Ok(MemoryReservation { pool: self.clone(), pages }),
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
    pub(crate) fn pages(&self) -> u64 { self.pages }
}

impl Drop for MemoryReservation {
    fn drop(&mut self) {
        // Every reservation subtracted these pages once; no other API can add
        // capacity. Releasing cannot exceed the fixed ceiling or wrap u64.
        self.pool.0.available.fetch_add(self.pages, Ordering::Release);
    }
}
