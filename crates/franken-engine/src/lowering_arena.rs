//! Region arena for the IR lowering pipeline (Tofte/Talpin-style regions).
//!
//! Every IR0 / IR1 / IR2 / IR3 intermediate produced *inside* a lowering pass
//! dies at the end of that pass — the only allocations that escape are the
//! `Vec`s owned by the returned `Ir3Module`. That lifetime alignment is exactly
//! the property region inference (Tofte & Talpin, 1994) exploits to replace
//! per-allocation `malloc`/`free` with a single bump pointer and an O(1) bulk
//! reset. `LoweringArena` wraps [`bumpalo::Bump`] so the scratch allocations on
//! the lowering hot path (the IR2→IR3 evaluation stack, per-call operand
//! collectors, array/object element lists) can be served from one contiguous
//! region and dropped together when the pass returns.
//!
//! The arena is deliberately a thin wrapper: it exposes only the operations the
//! lowering pipeline needs, so the `&LoweringArena` threaded through the passes
//! cannot be misused to allocate something that must outlive the region.
//!
//! See `docs/PERF_ALIEN2_ARENA_AUDIT.md` (bd-o4cbn.10.1) for the per-site
//! lifetime classification that drives which allocations are arena candidates.

use bumpalo::Bump;
use bumpalo::collections::Vec as ArenaVec;

/// A bump-allocated region scoped to a single IR lowering pass.
///
/// Construct one per pass, hand out `&LoweringArena` to the per-pass helpers,
/// and let the whole region drop (or call [`reset`](LoweringArena::reset) to
/// reuse the backing capacity) when the pass completes.
#[derive(Default)]
pub struct LoweringArena {
    bump: Bump,
}

impl LoweringArena {
    /// Create an empty arena.
    pub fn new() -> Self {
        Self { bump: Bump::new() }
    }

    /// Create an arena pre-sized to hold at least `bytes` before its first
    /// internal chunk growth. Useful when a pass can estimate its scratch
    /// footprint up front (e.g. from the IR2 op count).
    pub fn with_capacity(bytes: usize) -> Self {
        Self {
            bump: Bump::with_capacity(bytes),
        }
    }

    /// Drop every allocation in the region in O(1), retaining the backing
    /// capacity for reuse on the next pass.
    pub fn reset(&mut self) {
        self.bump.reset();
    }

    /// Allocate a single `value` in the region, returning a mutable reference
    /// whose lifetime is tied to the arena.
    pub fn alloc<T>(&self, value: T) -> &mut T {
        self.bump.alloc(value)
    }

    /// Create an empty arena-backed [`Vec`](bumpalo::collections::Vec).
    pub fn alloc_vec<T>(&self) -> ArenaVec<'_, T> {
        ArenaVec::new_in(&self.bump)
    }

    /// Create an arena-backed [`Vec`](bumpalo::collections::Vec) pre-sized to
    /// `capacity` elements — the arena equivalent of `Vec::with_capacity`.
    pub fn alloc_vec_with_capacity<T>(&self, capacity: usize) -> ArenaVec<'_, T> {
        ArenaVec::with_capacity_in(capacity, &self.bump)
    }

    /// Total bytes the region has currently reserved across its chunks. Exposed
    /// for instrumentation and tests; not part of the lowering contract.
    pub fn allocated_bytes(&self) -> usize {
        self.bump.allocated_bytes()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn new_and_default_are_equivalent() {
        let a = LoweringArena::new();
        let b = LoweringArena::default();
        // Both start empty (no live allocations).
        assert_eq!(a.alloc_vec::<u32>().len(), 0);
        assert_eq!(b.alloc_vec::<u32>().len(), 0);
    }

    #[test]
    fn alloc_returns_usable_mut_ref() {
        let arena = LoweringArena::new();
        let v = arena.alloc(7u64);
        *v += 35;
        assert_eq!(*v, 42);
    }

    #[test]
    fn alloc_vec_push_pop_len() {
        let arena = LoweringArena::new();
        let mut stack = arena.alloc_vec::<u32>();
        for r in 0..8 {
            stack.push(r);
        }
        assert_eq!(stack.len(), 8);
        assert_eq!(stack.last().copied(), Some(7));
        assert_eq!(stack.pop(), Some(7));
        assert_eq!(stack.len(), 7);
        // Slice deref coercion (used by the pipeline's `&[Reg]` helpers).
        let slice: &[u32] = &stack;
        assert_eq!(slice, &[0, 1, 2, 3, 4, 5, 6]);
    }

    #[test]
    fn alloc_vec_with_capacity_does_not_change_len() {
        let arena = LoweringArena::new();
        let v = arena.alloc_vec_with_capacity::<u32>(32);
        assert_eq!(v.len(), 0);
        assert!(v.capacity() >= 32);
    }

    #[test]
    fn arena_vec_drains_to_std_vec_in_order() {
        // Mirrors the pipeline pattern: collect scratch regs in the arena, then
        // drain into the owned IR3 instruction stream.
        let arena = LoweringArena::new();
        let mut args = arena.alloc_vec::<u32>();
        args.extend([10u32, 20, 30]);
        let drained: Vec<u32> = args.iter().copied().collect();
        assert_eq!(drained, vec![10, 20, 30]);
    }

    #[test]
    fn reset_reuses_capacity() {
        let mut arena = LoweringArena::with_capacity(1024);
        {
            let mut v = arena.alloc_vec_with_capacity::<u64>(64);
            for i in 0..64 {
                v.push(i);
            }
            assert!(arena.allocated_bytes() >= 64 * std::mem::size_of::<u64>());
        }
        arena.reset();
        // After reset the region is logically empty but retains backing chunks.
        assert!(arena.allocated_bytes() >= 1024);
        let v2 = arena.alloc_vec::<u64>();
        assert_eq!(v2.len(), 0);
    }

    #[test]
    fn multiple_independent_vecs_coexist() {
        let arena = LoweringArena::new();
        let mut a = arena.alloc_vec::<u32>();
        let mut b = arena.alloc_vec::<u32>();
        a.push(1);
        b.push(2);
        a.push(3);
        assert_eq!(&*a, &[1, 3]);
        assert_eq!(&*b, &[2]);
    }
}
