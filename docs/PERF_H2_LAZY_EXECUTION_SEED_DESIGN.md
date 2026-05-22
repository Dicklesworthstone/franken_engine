# PERF-H2 Lazy Execution Seed Design

## Overview

PERF-H2 implements lazy capture for `capture_execution_seed()` to eliminate repeated deep clones of interpreter state (registers, heap, function_prototypes) in the hot execution path. This optimization provides the highest cycle savings potential but carries the highest risk due to replay determinism requirements.

## 1. The Invariant (Precise Statement)

> For all program-state sequences `s_0, s_1, …, s_n` produced by IR3
> execution, and for any `i ≤ j`, let `S = capture_execution_seed_at(s_i)`.
> Then `reset_execution_state_from_seed(S)` invoked at `s_j` produces a
> program state `s_i'` such that:
>
> 1. `s_i'.registers == s_i.registers` byte-equal,
> 2. `s_i'.heap == s_i.heap` byte-equal,
> 3. `s_i'.function_prototypes == s_i.function_prototypes` byte-equal.

That's the load-bearing property. Any divergence is a correctness bug.

## 2. The Structure

```rust
enum ExecutionSeed {
    Lazy {
        epoch: u64,
        max_regs: u32,
    },
    Materialized {
        registers: Vec<Value>,
        heap: Heap,
        function_prototypes: FunctionPrototypes,
    },
}
```

## 3. Type-Enforced Write Discipline (THE LOAD-BEARING PIECE)

Rather than a manual audit checklist, the design wraps each seed-surface
field in `SeedTrackedField<T>` whose `DerefMut` calls
`InterpreterCore::before_seed_surface_write()` automatically:

```rust
pub(crate) struct SeedTrackedField<T> {
    value: T,
    // The owning InterpreterCore is responsible for epoch bump +
    // materialization; SeedTrackedField holds a back-pointer via &mut
    // borrow at access time (no Rc<RefCell> overhead on hot path).
}

impl<T> Deref for SeedTrackedField<T> {
    type Target = T;
    fn deref(&self) -> &T { &self.value }
}
```

For `DerefMut`, we need to call a method on the *owning* InterpreterCore
before yielding `&mut T`. Two implementation options:

**Option A (selected): Method-pair API.** `SeedTrackedField` does NOT
implement `DerefMut`. Mutable access is only via `core.mutate_<field>(|v: &mut T| { … })`
helpers on `InterpreterCore`. Each helper calls
`self.before_seed_surface_write()` then yields `&mut self.field.value` to
the closure. The borrow checker forbids constructing `&mut field.value`
outside these helpers. **Cannot be bypassed.**

**Option B: Builder/scope pattern.** A `SeedSurfaceWrite<'a>` RAII guard
constructed only via `core.begin_seed_surface_write()` exposes
`registers_mut`, `heap_mut`, etc. on drop it bumps the epoch. Slightly
more flexible but harder to enforce single-mutation.

Option A is simpler and tighter; selected.

## 4. The Protocol

- `capture_execution_seed` returns `Rc<RefCell<ExecutionSeed>>` of
  `Lazy{ epoch: self.seed_epoch, max_regs }`. Caller holds the Rc; the
  Weak goes into `self.pending_lazy_seeds`.
- `mutate_registers` / `mutate_heap` / `mutate_function_prototypes`:
  1. Call `self.materialize_pending_lazy_seeds()` — drains Weak refs,
     materializes any still-live Lazy seed *with the pre-mutation state*.
  2. Bump `self.seed_epoch = self.seed_epoch.wrapping_add(1)`.
  3. Yield `&mut self.field.value` to the closure.
- `reset_execution_state_from_seed(Rc<RefCell<ExecutionSeed>>)`:
  - If `seed` is `Lazy { epoch }` and `self.seed_epoch == epoch`: no-op.
  - If `seed` is `Materialized {…}`: apply the contents.
  - If `seed` is `Lazy { epoch }` and `self.seed_epoch != epoch`:
    **invariant violation** (write happened without materializing).
    `panic!()` with full diagnostic — this is a bug, not a runtime case.

## 5. Self-Cost Guardrail

`Rc<RefCell<ExecutionSeed>>` allocates on the heap per `capture_execution_seed`
call. Eager clone allocates a 256-Value Vec each call. We need:

> total_cost(lazy) = Rc_alloc + 0× clone (no write) OR Rc_alloc + clone_size (write)
> total_cost(eager) = clone_size

The Rc allocation is ~80 bytes (well below the 8 KiB register-Vec clone).
But on "no write" paths the lazy version wins outright. On "write"
paths the lazy version costs Rc_alloc *extra*. We bench in H2.6 to
confirm net positive.

If H2.6 measures a *regression*, fallback design: use `Box<Cell<ExecutionSeed>>`
or even a flat `(epoch: u64, MaybeUninit<ExecutionSeed>)` per
captured-seed slot inside InterpreterCore (no heap alloc). H2.6 documents
the chosen design.

## Implementation Strategy

### Phase 1: Type Infrastructure (H2.2)
1. Introduce `SeedTrackedField<T>` with read-only `Deref`
2. Add `ExecutionSeed` enum and epoch tracking to `InterpreterCore`
3. Implement `mutate_*` helper methods with pre-mutation materialization

### Phase 2: Write-Site Migration (H2.2)
Convert all direct field access to use the helper methods:
- `self.registers[i] = v;` → `self.mutate_registers(|r| r[i] = v);`
- `self.registers.push(v);` → `self.mutate_registers(|r| r.push(v));`
- `self.heap.insert(k, v);` → `self.mutate_heap(|h| h.insert(k, v));`

### Phase 3: Verification (H2.3-H2.5)
1. Unit tests for write tracking exhaustiveness
2. Property tests comparing lazy vs eager behavior
3. Gate validation with replay-coverage and metamorphic suites

## Risk Mitigation

1. **Type Safety**: The `SeedTrackedField` design makes write-site bypasses impossible at compile time
2. **Epoch Validation**: Lazy seeds that survive writes trigger panic with diagnostic information
3. **Incremental Migration**: Each IR3 handler family gets its own commit for reviewability
4. **Comprehensive Testing**: Multiple test layers verify correctness before bench validation

## Performance Expectations

- **Best Case** (no writes between capture/reset): ~50× improvement (eliminate all clones)
- **Worst Case** (writes on every capture): ~1.02× cost (Rc allocation overhead)
- **Typical Case** (mixed workload): 10-20× improvement based on write frequency

## Compatibility

This change is purely internal to `baseline_interpreter.rs`. No public API changes are required. The `capture_execution_seed` and `reset_execution_state_from_seed` methods maintain identical signatures and behavior guarantees.