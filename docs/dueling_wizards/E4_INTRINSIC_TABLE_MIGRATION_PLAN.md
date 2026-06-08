# E4 — Intrinsic-Table Migration Plan (bd-fqlfw.4.5 / E4.T5)

> How the ~97 `BuiltinFunctionKind` variants + prototype methods move off the hand-wired
> "5-seam assembly line" onto the declarative intrinsic table — **family-by-family,
> non-breaking, and reversible**, with the legacy `match` shrinking monotonically.
>
> Depends on: E4.T1 schema (`intrinsics_table.rs`, landed) + E4.T2 codegen
> (`intrinsics_codegen.rs`, landed). Feeds: E4.T3 (first family migration) + E4.T4 (uniform
> IFC propagation).

## Why migrate (the cost being removed)

Today every builtin/prototype method touches **five scattered sites** in the 1.25 MB
`baseline_interpreter.rs` — a `BuiltinFunctionKind` variant (~line 601), a name/constructor
mapping, an exec arm in `dispatch_builtin_function` (~5293), prototype wiring in
`string_property_value` (~11561) / `array_prototype_method` (~12000) /
`collection_prototype_method` (~12044), plus a `lowering_gap_inventory` entry. Each addition
churns IR3 goldens and **collides between agents** (the session memory records repeated
stand-downs and duplicated work, e.g. the ES2023 `toSorted`/`toReversed` collision). The table
collapses those five edits into **one reviewable row + one hand-written impl fn**, with the
dispatch arm, capability tag, IFC-propagation glue, and gap-inventory entry generated
consistently by construction (E4.T2).

## Migration order (by edit-frequency / collision pain)

| # | Family | Why this order | Dispatch seam today |
|---|---|---|---|
| 1 | **`String.prototype.*`** | Highest edit churn + collision rate in the memory; large, regular surface; ideal first proof (E4.T3). | `string_property_value` |
| 2 | **`Array.prototype.*`** | Second-highest churn; exercises variadics, callbacks (escape hatch), `thisArg`. | `array_prototype_method` |
| 3 | **Collections (`Map`/`Set`/`WeakMap`/`WeakSet`/`Date`)** | Brand-checked receivers (`ThisCoercion::RequireType`); validates the collection seam. | `collection_prototype_method` |
| 4 | **Global builtins (`console.*`, `require`, `Math.*`, `JSON.*`)** | Capability-bearing globals (`Console`/`ModuleLoad`); validates `ReceiverKind::Global` + capability glue. | direct `dispatch_builtin_function` arms |
| 5 | **`Object.*` / `Number.*` / `Reflect`** | Static + reflection surfaces; some need the escape hatch. | mixed |
| 6 | **`Proxy` / exotic** | Mostly escape-hatch (`ImplBinding::Manual`); migrate last, documented. | bespoke |

## Per-family recipe (each family = one shippable, reversible PR)

1. **Express** the family's methods as `IntrinsicRow`s (E4.T1 schema), one row each;
   irregular methods use `ImplBinding::Manual` with a documented reason + site (never contort
   the schema).
2. **Generate** the glue from the rows via `intrinsics_codegen::generate_glue` (E4.T2):
   registry + dispatch plan + gap-inventory entries.
3. **Wire alongside legacy (coexist).** Add a generated-dispatch path for *this family only*,
   guarded so the legacy `match` still serves it until parity is proven. No legacy arms removed
   yet — this step is purely additive (the lesson from the memory: coexist, then flip).
4. **Prove parity.** Byte-identical IR3 goldens + the family's existing unit/integration tests
   pass through the generated path; the differential oracle (E2) shows no divergence; the
   `E4.TEST` capstone's parity golden is green.
5. **Flip + delete.** Switch the family to the generated path and remove its now-dead legacy
   arms. The legacy `match` shrinks; the gap inventory updates by construction.
6. **IFC.** Confirm each row's declared `IfcPropagation` reproduces (or fixes) the family's
   label behavior — the uniform per-row policy that removes the hand-wired under-tainting class
   (E4.T4, guards `bd-0zybl`/`bd-ooaka`).

## Invariants held throughout

- **Non-breaking:** legacy and generated paths coexist per family until parity is proven; a
  failed parity check blocks the flip, never ships a divergence.
- **Reversible:** the flip is a one-line switch per family; rollback re-enables the legacy arms
  (kept in git history) without touching semantics.
- **Glue-only:** generated code is data + wiring; the hand-written impl fns hold all semantics
  (reviewer line-of-sight preserved — mandatory in a security runtime).
- **Monotonic:** the legacy `match` only ever shrinks; a regression that needs legacy back is a
  parity failure, not a silent re-expansion.
- **Collision-aware:** because every migration touches the contended `baseline_interpreter.rs`,
  reserve the family's seam via agent-mail + `git grep` the methods before starting, and land
  per-hunk so peer WIP is preserved.

## Tracking checklist

| Family | Rows authored | Glue wired (coexist) | Parity green | Flipped (legacy removed) | Bead |
|---|---|---|---|---|---|
| String.prototype | ☐ | ☐ | ☐ | ☐ | E4.T3 (`bd-fqlfw.4.3`) |
| Array.prototype | ☐ | ☐ | ☐ | ☐ | follow-on |
| Collections | ☐ | ☐ | ☐ | ☐ | follow-on |
| Globals | ☐ | ☐ | ☐ | ☐ | follow-on |
| Object/Number/Reflect | ☐ | ☐ | ☐ | ☐ | follow-on |
| Proxy/exotic (escape hatch) | ☐ | ☐ | ☐ | ☐ | follow-on |

Definition of done for E4 overall: an agent adds a builtin by appending **one table row + one
impl fn** (no surgery on the 1.25 MB file), the gap inventory updates by construction, IFC
propagation is uniform per row, and the legacy `match` has shrunk to only the documented
escape-hatch cases.
