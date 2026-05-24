# PERF-ALIEN-2.1 — Arena-Allocation Audit (IR Lowering)

**Bead:** `bd-o4cbn.10.1` (parent `bd-o4cbn.10` — Region arena (bumpalo) for IR
lowering, Tofte/Talpin-style)
**Agent:** AmberCanyon
**Date:** 2026-05-24
**Scope:** `lowering_pipeline.rs`, `ir_contract.rs`, `static_semantics.rs`

---

## 1. Method

1. Enumerated every production (non-`#[cfg(test)]`) `Box::new`, `Vec::new`,
   `Vec::with_capacity`, `vec!`, and `String`-producing call site in the three
   target files. Test-module boundaries: `lowering_pipeline.rs` L8234,
   `static_semantics.rs` L1747, `ir_contract.rs` L2649. Sites above those lines
   are production; below are test fixtures (excluded).
2. For each production site, classified its **lifetime** against the single
   load-bearing question for region allocation:

   > Does the allocation **escape into the returned `Ir3Module`** (the lowering
   > output), or does it **die at the end of the lowering pass**?

   Only allocations that die at end-of-pass are arena candidates. Escaping
   allocations must remain `std` heap allocations owned by `Ir3Module`.

## 2. The lifetime model (what escapes vs. what is scratch)

The escape boundary is precise because the **IR3 output types are narrow**:

| Output type (`ir_contract.rs`) | Owned heap fields that escape lowering |
|---|---|
| `Ir3Module` | `instructions: Vec<Ir3Instruction>`, `constant_pool: Vec<String>`, `function_table: Vec<Ir3FunctionDesc>`, `required_capabilities: Vec<CapabilityTag>` |
| `Ir3FunctionDesc` | **scalars only** — `entry`, `arity`, `frame_size`, `name: Option<String>`, `is_generator`. **No** `param_names`/`free_vars`/`body_ops` vectors. |
| `Ir3Instruction::Call` / array / template ops | operands are `RegRange { start, count }` — **register ranges, not owned `Vec`s** |

Two consequences drive the whole audit:

- **IR3 operands are register ranges, not operand vectors.** A call like
  `f(a, b, c)` is lowered by collecting the argument registers into a scratch
  `Vec`, draining it into a run of `Move` instructions, and emitting
  `Call { args: RegRange { start, count }, .. }`. The scratch `Vec` is consumed
  on the spot and dropped — its contents are copied (cheap `Reg = u32` copies)
  into `ir3.instructions`. Every per-expression operand collector is therefore
  pure scratch.
- **`Ir3FunctionDesc` carries no vectors.** The deferred function-body buffers
  (`body_ops: Vec<Ir1Op>`, `param_names`, `free_vars`, `body_bindings`) are
  intermediate IR1-level structures consumed when each deferred body is lowered
  into `ir3.instructions`, then dropped. They do **not** survive into the
  function table.

So the only allocations that must outlive the pass are: the instruction
vector, the string constant pool, the function-descriptor table, the capability
set, and the `ScopeResolution.bindings` produced by `static_semantics`. Almost
everything else allocated during a lower is scratch.

## 3. Site table (≥10 sites)

`Lives until` column: **EOP** = end of lowering pass (arena candidate);
**Ir3Module** = escapes into the returned module (keep on `std` heap).

| File:line | Pattern | Binding | Lives until | Decision |
|---|---|---|---|---|
| `lowering_pipeline.rs:3068` | `Vec::with_capacity(32)` | `value_stack: Vec<Reg>` — central IR2→IR3 evaluation stack | EOP | **Arena** (top candidate; one per function lower). Also a buffer-pool candidate — see §4. |
| `lowering_pipeline.rs:3282` | `Vec::with_capacity(count)` | `args` for `Ir1Op::Call` | EOP | **Arena.** Drained into `Move`s; `Call` keeps only a `RegRange`. |
| `lowering_pipeline.rs:3312` | `Vec::with_capacity(count)` | `args` (second call shape) | EOP | **Arena.** Same as above. |
| `lowering_pipeline.rs:3141`,`3157` | `Vec::new()` | `args` (zero-arg/unknown-count call paths) | EOP | **Arena.** Same drain-and-drop pattern. |
| `lowering_pipeline.rs:3770`,`4793` | `Vec::with_capacity(cnt)` | `elements` for array literals | EOP | **Arena.** Element regs emitted as a `RegRange`. |
| `lowering_pipeline.rs:3810`,`4830` | `Vec::with_capacity(cnt)` | `properties` for object literals | EOP | **Arena.** Property regs emitted as a `RegRange`. |
| `lowering_pipeline.rs:4059`,`5072` | `Vec::with_capacity(count.min(1024))` | `arg_regs` (specialized call) | EOP | **Arena.** Scratch register list. |
| `lowering_pipeline.rs:4099`,`5030` | `Vec::with_capacity(total.min(1024))` | `part_regs` (template-literal parts) | EOP | **Arena.** Scratch register list. |
| `lowering_pipeline.rs:4379` | `Vec::new()` | `seen_ids` — free-var dedup scratch | EOP | **Arena.** Pure dedup buffer; result copied into a `BTreeMap`. |
| `lowering_pipeline.rs:2448`,`2559`,`2663`,`7352`,`7433`,`7563`,`7644` | `Vec::with_capacity` / `Vec::new` | `body_ops` / `m_body_ops`: deferred function-body `Vec<Ir1Op>` | EOP | **Arena.** Lowered into `ir3.instructions`, then dropped; absent from `Ir3FunctionDesc`. |
| `lowering_pipeline.rs:2450`,`2561`,`7353`… | `Vec::with_capacity(32)` / `Vec::new` | `body_bindings` | EOP | **Arena.** Resolution scratch for deferred bodies. |
| `lowering_pipeline.rs:2432`,`2435` | `Vec::with_capacity` | `param_names: Vec<String>`, `destructure_params` | EOP | **Arena** for the `Vec` spine; the `String` names are interned into `constant_pool` (escape) or dropped — see §5. |
| `lowering_pipeline.rs:2610`,`2712`,`7605`,`7689` | `Vec::new()` | `free_vars: Vec<String>` (closure metadata) | EOP | **Arena** for spine; consumed into the closure-lowering map, not in `Ir3FunctionDesc`. |
| `lowering_pipeline.rs:3071` | `Vec::<PendingJump>::new()` | `pending_jumps` — forward-jump backpatch list | EOP | **Arena.** Resolved before the pass returns. |
| `lowering_pipeline.rs:3063` (`ir3.instructions.reserve`) | `Vec` (field) | `ir3.instructions: Vec<Ir3Instruction>` | **Ir3Module** | **Keep std heap.** This *is* the output. |
| `ir_contract.rs:1937`–`1945` | struct fields | `instructions`, `constant_pool`, `function_table`, `required_capabilities` | **Ir3Module** | **Keep std heap.** Output-owned. |
| `static_semantics.rs:617`,`657`,`750`,`840`,`954`,`1026`,`1076`,`1449`,`1492` | `Vec::new()` | per-scope `*_bindings: Vec<ResolvedBinding>` | EOP* | **Arena for the temporaries.** Each scope's accumulator is merged/extended into the parent result; the temporary spine dies. The *contents* land in the escaping `ScopeResolution.bindings`. |
| `static_semantics.rs:1659`,`1678` | `Vec::new()` | `refs` — reference-collection scratch | EOP | **Arena.** Analysis scratch, not returned. |
| `lowering_pipeline.rs:295`,`307` | `Box::new(UnsupportedSyntaxDiagnostic …)` | error-enum payload box | escapes as `Err` | **Keep.** Cold error path; box exists to shrink the error enum, not for speed. Not an arena candidate. |

**Production `Box::new` finding:** `static_semantics.rs` has **0** production
`Box::new` (all 85 are test-fixture AST construction); `lowering_pipeline.rs`
has only the **2 cold error-diagnostic boxes** above (the other 103 are
test-fixture AST). `ir_contract.rs` has **0**. There is therefore **no
hot-path `Box`-of-IR-node allocation to arena-ify** — the lowering hot path
allocates `Vec`s and `String`s, not boxed nodes.

## 4. Relationship to already-shipped buffer pooling (H4.3 / H2.x)

`value_stack`, `args`, and the deferred `body_ops` buffers overlap with the
reusable-buffer direction already shipped in `EncodeBufferPool` (commit
`f5b420a7`, H4.3) and the H2.x write-site work. Guidance for ALIEN-2.2:

- A **buffer pool** is the better fit for a *single* buffer reused across many
  iterations of the same shape (e.g. one `value_stack` reset per function).
- A **region arena** is the better fit for the *many heterogeneous,
  short-lived* allocations within one lowering pass (per-expression `args`,
  `elements`, `properties`, `arg_regs`, `part_regs`, `seen_ids`, plus each
  deferred body's `body_ops`/`body_bindings`). These are too numerous and too
  varied in type to pool individually; a single `LoweringArena` reset once per
  `lower()` call captures them all with one bump-pointer region.

Recommend ALIEN-2.2 introduce a `LoweringArena` scoped to one `lower_ir2_to_ir3`
(and the deferred-body sub-lowers) invocation, holding the per-expression
operand collectors and deferred IR1-op buffers, and leave `value_stack` to the
existing pool mechanism (or fold it in if measurement favors the arena).

## 5. Caveats / constraints recorded for ALIEN-2.2

1. **`#![forbid(unsafe_code)]` is unaffected.** `bumpalo` uses `unsafe`
   *internally*, but `forbid(unsafe_code)` is a per-crate lint — depending on
   `bumpalo` does not introduce `unsafe` into `frankenengine-engine` source.
   No constraint violation.
2. **Arena-allocated collections cannot move into `std::Vec` without a copy.**
   This is fine here precisely because every arena candidate is *drained by
   copy* into `ir3.instructions` (`Reg`/`u32` copies via `Move` emission) and
   never moved wholesale into the output. Use `bumpalo::collections::Vec<'a, _>`
   for the scratch collectors.
3. **Strings are a separate optimization.** Identifier names and literals flow
   into `constant_pool: Vec<String>` (escapes) or into the
   constant-pool interner (`pool.push(value.to_string())`, L26). String
   interning / arena-backed `&str` is **out of scope for ALIEN-2** — track
   separately; do not arena-allocate strings that are cloned into the pool.
4. **`static_semantics` temporaries escape by content.** The per-scope
   `*_bindings` Vecs are merged into `ScopeResolution.bindings`. Arena-allocate
   the *temporary spines* only; the merged result must remain `std`-owned. Lower
   payoff than the lowering-pipeline scratch — prioritize the lowering pipeline.
5. **Determinism preserved.** Arena allocation changes *where* bytes live, not
   iteration order or values; canonical-bytes output is unchanged. No impact on
   replay/golden-vector determinism (BTreeMap ordering etc. unchanged).

## 6. Acceptance check

- Sites enumerated: **19 rows / ≥30 individual call sites** (≥10 required). ✅
- Per-site lifetime rationale recorded. ✅
- Key architectural finding: IR3 uses `RegRange` operands and a scalar-only
  `Ir3FunctionDesc`, so per-expression operand collectors and deferred-body
  buffers are pure scratch — the prime arena target — while
  `instructions`/`constant_pool`/`function_table` must stay `std`-owned. ✅
