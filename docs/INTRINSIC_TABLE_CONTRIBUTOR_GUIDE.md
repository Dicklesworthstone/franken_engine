# Adding a Builtin — Intrinsic Table Contributor Guide

> Owning bead: `bd-fqlfw.4.7` (E4.DOC). Companion to the E4 epic
> (`bd-fqlfw.4`): declarative builtin/prototype codegen.

This guide is for adding a JavaScript builtin or prototype method
(`String.prototype.charAt`, `Date.now`, `Array.prototype.concat`, …) to the
runtime. The intrinsic table makes this **one table row plus one hand-written
implementation function** — no edits to the 31,914-line
`baseline_interpreter.rs` dispatch wiring, no hand-maintained gap-inventory
entry, and no per-site information-flow-control (IFC) code.

Source of truth: [`intrinsics_table.rs`](../crates/franken-engine/src/intrinsics_table.rs)
(schema), [`intrinsics_codegen.rs`](../crates/franken-engine/src/intrinsics_codegen.rs)
(codegen). Verify gate: [`scripts/run_dw_intrinsic_table.sh`](../scripts/run_dw_intrinsic_table.sh).

---

## The model: a row is data, the impl fn is behaviour

The table separates two concerns that used to be smeared across a five-seam
hand edit:

| Layer | What it holds | Where it lives |
|---|---|---|
| **Row** (`IntrinsicRow`) | *Data*: name, receiver shape, arity, capability, IFC policy, the impl fn's **identifier**, conformance ref, gap status. | one `IntrinsicRow` literal in the `define_intrinsics!` block |
| **Impl fn** | *Behaviour*: the actual JS semantics. | one hand-written `fn` named by the row |

**The glue-only rule (load-bearing).** Codegen (`generate_glue`) expands rows
into a name→row registry, a dispatch plan, and gap-inventory entries — all
*data*. It never emits semantics: a `DispatchTarget::Generated { impl_fn }`
carries the *identifier* of a hand-written fn, never a code body. This keeps a
reviewer's line of sight to where behaviour comes from, which is mandatory in a
security runtime. The capstone test
`generated_glue_contains_identifiers_not_semantic_bodies` enforces it.

---

## Step by step

1. **Add one row** to the `define_intrinsics! { … }` block in
   `intrinsics_table.rs` (the single edit site for declaring a builtin). Fill in
   every field (see the schema below).
2. **Write the impl fn** named by `ImplBinding::Generated { impl_fn: "…" }`. It
   holds the JS semantics and is wired into the interpreter dispatch seam by the
   per-family migration (E4.T3/T5). Its result-register label is derived
   automatically from the row's `ifc` policy by
   `InterpreterCore::intrinsic_result_label` — you do **not** hand-write a label
   join.
3. **Add the conformance ref** (`conformance:` field) pointing at the backing
   Test262 path, e.g. `"test262:built-ins/String/prototype/charAt"`. Use `""`
   only if none is wired yet (and then `gap_status` must not be `Resolved`).
4. **Run the gate**: `./scripts/run_dw_intrinsic_table.sh ci`. It re-asserts the
   glue-only rule, the IFC regression, the gap-inventory lockstep, and the
   parity/IFC test suites, and emits a content-addressed audit bundle.

The dispatch arm and the `lowering_gap_inventory` entry are **generated** from
the row — you never hand-maintain them, and the SYNC truth-gate
(`every_table_row_generates_gap_inventory_entry_without_drift`) fails closed if
they drift from the table.

---

## The `IntrinsicRow` schema

| Field | Type | How to choose |
|---|---|---|
| `name` | `&'static str` | Canonical JS name, e.g. `"String.prototype.trim"` or `"Date.now"`. Must be unique (codegen fails closed on a duplicate). |
| `receiver` | `ReceiverKind` | The dispatch seam: `Global` (no `this`, e.g. `Math.max`), `String`, `Array`, `Object`, `Number`, or a `__type`-tagged collection (`Map`/`Set`/`Date`). |
| `this_coercion` | `ThisCoercion` | `None` (global fn), `ToString` (String.prototype.*), `ToObject`, or `RequireType("Map")` (brand check — fails closed with a `TypeError` on the wrong receiver). |
| `arity` | `Arity` | `Exact(n)`, `AtLeast(n)`, `Range { min, max }` (optional trailing args), or `Variadic { required }`. |
| `capability` | `Option<RuntimeCapability>` | The typed authority the call requires, or `None` for a pure builtin. Unknown hostcall tags map to no capability and are rejected at the membrane. |
| `ifc` | `IfcPropagation` | The result-label propagation policy — see the decision guide below. This is the security-critical field. |
| `impl_binding` | `ImplBinding` | `Generated { impl_fn: "name" }` for the common case (codegen routes the seam to your hand-written fn), or `Manual { reason, site }` for an irregular builtin that resists table dispatch (records *why* and *where* so coverage accounting stays honest). |
| `conformance` | `&'static str` | Test262 anchor, or `""` if none yet. |
| `gap_status` | `GapStatus` | `Resolved` (implemented + conformance-backed), `Partial("…residual…")`, or `Planned` (declared, not yet implemented). |

---

## Choosing the IFC policy (the security-critical field)

The runtime derives a builtin result's information-flow label from the row's
`ifc` policy **alone**, so propagation cannot be forgotten per-site — this is
the mechanism that retired the `bd-0zybl` under-tainting class, where
`secret.toUpperCase()` could launder a `Secret` receiver's result to a stale
`Public` label. Pick the policy by how the result's sensitivity depends on the
inputs:

| Policy | Result label is… | Use for |
|---|---|---|
| `PropagateReceiverLabel` | the receiver's label | arg-free prototype methods (`trim`, `toUpperCase`) — the result is derived only from the receiver. |
| `JoinReceiverAndArgs` | `join(receiver, all arg labels)` | prototype methods that read arguments (`charAt`, `concat`, `slice`) — the result depends on both. |
| `JoinArgs` | `join(arg labels)` only | static fns with no meaningful receiver (`Math.max`). |
| `Constant(LabelClass)` | a fixed label, regardless of inputs | inputs-independent results (`Date.now` → `Public`). |
| `Custom("fn_name")` | computed by a named hand-written fn | irregular, callback-dependent flows (e.g. `Array.prototype.reduce`, whose result label depends on the callback's return — `bd-ooaka`). Codegen never guesses these; the documented manual site owns the flow. |

Rule of thumb: if the result can carry information from a field of `this`, the
policy must include the receiver label; if it can carry information from an
argument, it must join the argument labels. When in doubt, join more (an
over-tainted result fails closed; an under-tainted one leaks).

---

## Fully worked example: `String.prototype.charAt`

The row (verbatim from `intrinsics_table.rs`; its exact generated glue is pinned
by the `one_table_row_to_generated_glue_snapshot_is_stable` capstone test, so
this example cannot silently drift):

```rust
IntrinsicRow {
    name: "String.prototype.charAt",
    receiver: ReceiverKind::String,                 // String.prototype.* seam
    this_coercion: ThisCoercion::ToString,          // box `this` via ToString
    arity: Arity::Range { min: 0, max: 1 },         // charAt([index])
    capability: None,                               // pure builtin, no authority
    ifc: IfcPropagation::JoinReceiverAndArgs,        // reads the index arg → join receiver + args
    impl_binding: ImplBinding::Generated { impl_fn: "string_char_at_impl" },
    conformance: "test262:built-ins/String/prototype/charAt",
    gap_status: GapStatus::Resolved,
}
```

What this single row buys you, all derived by `generate_glue` and verified by
the gate:

- **Registry**: `"String.prototype.charAt"` → this row, for O(log n) lookup.
- **Dispatch**: routes to the hand-written `string_char_at_impl` (you write that
  fn; the row names it).
- **IFC**: the result register's label is computed as
  `join(receiver_label, arg_labels)` at the dispatch seam — no hand-written join.
- **Gap inventory**: a generated `Resolved` entry with the Test262 anchor; it
  cannot drift from the row.

You wrote one row and one `fn`. You did not touch the dispatch match, the gap
inventory, or any IFC code.

---

## Migration / coexistence note

The intrinsic table is being adopted family by family (E4.T5). During
migration, a legacy hand-wired arm and its table row can coexist: the table
must change **nothing observable** — the PARITY golden
(`family_covers_the_exact_legacy_method_set` and the byte-identical behaviour /
IR3 goldens in
[`intrinsic_table_string_family_migration.rs`](../crates/franken-engine/tests/intrinsic_table_string_family_migration.rs))
asserts the migrated family matches the pre-migration legacy match
byte-for-byte.
When adding a method to an already-migrated family, add only the row + impl fn;
when migrating a new family, follow E4.T3's pattern (move the semantics into
named impl fns, then declare the rows).

---

## Verifying your change

```bash
# Full gate: glue-only guard, IFC regression, gap-inventory lockstep,
# parity + codegen + IFC test suites, audit bundle under
# artifacts/dw_intrinsic_table/<ts>/.
./scripts/run_dw_intrinsic_table.sh ci

# Re-verify a preserved bundle (content-hash + pass-outcome check):
./scripts/e2e/dw_intrinsic_table_replay.sh bundle <bundle-dir>
```

The gate is rch-backed like the other `run_dw_*.sh` gates. If the remote build
fleet is unavailable, run the underlying tests locally instead:

```bash
RCH_CARGO_WRAPPER_BYPASS=1 cargo test -p frankenengine-engine \
  --test intrinsic_table_string_family_migration \
  --lib intrinsics_codegen string_intrinsic_table_parity_tests
```

A correct change keeps every capstone gate green: the snapshot is stable, the
generated glue holds only identifiers, every row has a drift-free gap entry, and
each row's declared IFC policy is secret-safe.
