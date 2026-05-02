# Semantic Donor Specification (V8/QuickJS Observable Semantics)

This document is the implementation source of truth for donor-derived semantics in `franken_engine`.

It defines WHAT behavior must be preserved, not HOW donor engines implement it.

Companion governance contracts:
- `docs/DONOR_EXTRACTION_SCOPE.md` (allowlist/denylist + workflow + exception policy)
- `docs/RUNTIME_CHARTER.md` (native-only runtime ownership)

Plan references:
- `PLAN_TO_CREATE_FRANKEN_ENGINE.md` section `4.1` (Spec-First Hybrid Bootstrap)
- `PLAN_TO_CREATE_FRANKEN_ENGINE.md` section `10.1` item `bd-3u5`

## 1. Purpose And Scope

This spec captures observable ECMAScript and runtime-facing semantics harvested from donor corpora (`legacy_v8`, `legacy_quickjs`, `test262`, lockstep traces) that FrankenEngine must match for compatibility.

This spec does not authorize donor architecture mirroring. It is strictly a semantic contract for native Rust implementations.

Security-epoch semantics are FrankenEngine runtime-security semantics, not donor-engine behavior. The current executable contract is fail-closed validation of explicit epoch metadata against a caller-supplied current epoch or persisted frontier. A local `EpochTracker` instance is not, by itself, a durable cross-restart authority; any claim of restart-monotonic epoch enforcement must cite the persistent checkpoint/frontier store that supplies the epoch floor at startup.

## 2. Semantic Entry Schema (Machine-Readable Contract)

Each semantic requirement is represented by a canonical entry. Entries must be serializable to JSON/YAML for conformance tooling.

Canonical schema:

```yaml
semantic_id: SEM-PRM-001
category: promise-microtasks
observable_contract: >
  Promise reaction jobs are enqueued FIFO within a single microtask checkpoint;
  jobs added during checkpoint execution run in the same checkpoint after already queued jobs.
edge_cases:
  - chained then/catch with mixed sync throws
  - nested queueMicrotask inside then callback
compatibility_impact: high
test262_refs:
  - test/built-ins/Promise/prototype/then/S25.4.5.3_A5.1_T1.js
lockstep_fixture_refs:
  - artifacts/lockstep/promise_fifo_jobs_seed_v1.json
waiver_policy: explicit-waiver-required
status: required
```

Required fields:
- `semantic_id`
- `category`
- `observable_contract`
- `edge_cases`
- `compatibility_impact`
- `test262_refs`
- `lockstep_fixture_refs`
- `waiver_policy`
- `status`

## 3. Semantic Domain Catalog

The following semantic domains are mandatory for compatibility tracking.

| Domain | Required Outcome | Compatibility Impact |
|---|---|---|
| lexical-scope | `let`/`const` TDZ + block scope behavior matches donor-observable semantics | high |
| function-and-this | call/apply/bind and strict/non-strict `this` binding behavior is stable | high |
| objects-and-descriptors | property descriptor invariants, defineProperty errors, prototype lookup behavior | high |
| equality-and-coercion | SameValue/SameValueZero/`===`/`==` observable outcomes | medium |
| arrays-and-iteration | sparse array holes, iterator close protocol, for-of abrupt completion behavior | high |
| promises-and-microtasks | deterministic microtask ordering and rejection propagation semantics | high |
| async-await | await suspension/resume/error propagation behavior | high |
| modules | static import/export linking errors and execution ordering | high |
| errors-and-exceptions | typed error surfaces and throw/catch/finally ordering | high |
| numeric-and-bigint | `NaN`, `-0`, bigint conversion and overflow-visible semantics | medium |
| json-and-serialization | `JSON.stringify/parse` edge behavior and ordering constraints where mandated | medium |
| regexp-and-strings | unicode/escape semantics and match group behavior | medium |
| runtime-trust-epochs | explicit epoch metadata is validated fail-closed against an authoritative current epoch/frontier | high |

## 4. Compatibility-Critical Semantic Entries

Each entry below is binding for conformance and lockstep gates.

### Scope and binding semantics
- `SEM-LEX-001`: TDZ access before initialization throws `ReferenceError` in matching control-flow contexts.
- `SEM-LEX-002`: Shadowed bindings resolve nearest lexical environment deterministically.
- `SEM-FUN-001`: strict-mode unbound calls preserve `undefined` `this`; non-strict global binding behavior is explicit by lane policy.
- `SEM-FUN-002`: arrow functions capture lexical `this` and `arguments` behavior.

### Objects/prototypes/descriptors
- `SEM-OBJ-001`: `Object.defineProperty` invariant violations throw consistently.
- `SEM-OBJ-002`: prototype-chain resolution order and `hasOwnProperty` distinctions are stable.
- `SEM-OBJ-003`: non-configurable property transitions obey ECMAScript constraints.

### Equality/coercion/numeric
- `SEM-EQL-001`: `NaN !== NaN`, `Object.is(NaN, NaN) === true`, `Object.is(-0, 0) === false`.
- `SEM-EQL-002`: abstract equality coercion follows observable ECMAScript behavior for primitives.
- `SEM-NUM-001`: bigint/number conversion throws when precision-loss constraints require it.

### Arrays/iterators/generators
- `SEM-ARR-001`: sparse arrays preserve hole semantics in iteration and mapping methods.
- `SEM-ITR-001`: iterator closing (`return`) runs on abrupt completion in `for...of`.
- `SEM-GEN-001`: generator resume/throw/return transitions preserve completion semantics.

### Promises/async/microtasks
- `SEM-PRM-001`: promise reaction jobs execute FIFO within microtask checkpoints.
- `SEM-PRM-002`: rejection propagation order for chained handlers is deterministic.
- `SEM-PRM-003`: nested microtask scheduling preserves same-turn checkpoint semantics.
- `SEM-ASY-001`: `await` unwrap behavior for thenables follows observable ordering constraints.
- `SEM-ASY-002`: async throw timing maps to rejected promise behavior consistently.

### Modules/errors/serialization
- `SEM-MOD-001`: module dependency resolution errors are surfaced before evaluation side-effects.
- `SEM-MOD-002`: cyclic module execution ordering follows deterministic link/evaluate phases.
- `SEM-ERR-001`: `try/catch/finally` completion order and rethrow behavior is deterministic.
- `SEM-ERR-002`: native error type classification (`TypeError`, `RangeError`, etc.) is stable.
- `SEM-JSN-001`: `JSON.stringify` key omission behavior for `undefined`, functions, and symbols is stable.
- `SEM-JSN-002`: compound JSON arrays/objects materialize as heap-backed runtime values instead of descriptor placeholders.
- `SEM-JSN-003`: `JSON.stringify` over compound runtime values uses deterministic own-key ordering, container-sensitive omission/nulling rules, and explicit cycle failure.
- `SEM-JSN-004`: unsupported JSON extension surfaces (`reviver`, `replacer`, `space`, unsupported numeric forms) are explicit and fail closed rather than being silently approximated.
- `SEM-REG-001`: regexp unicode class/match group behavior aligns with test262 coverage target.

### Runtime trust-state semantics
- `SEM-SEC-001`: signed runtime artifacts carrying epoch metadata are accepted only when the verifier supplies an authoritative current epoch/frontier and the artifact's validity window contains that epoch; future, expired, inverted-window, or regressed-frontier cases fail closed.
- `SEM-SEC-002`: cross-restart monotonic epoch claims require a durable persisted frontier/checkpoint source. In-process trackers may stamp and validate metadata but must not be treated as evidence that the runtime survives restart rollback without that persisted frontier.

Compound JSON representation and unsupported-edge policy are defined in
[`docs/RGC_COMPOUND_JSON_RUNTIME_CONTRACT_V1.md`](./RGC_COMPOUND_JSON_RUNTIME_CONTRACT_V1.md).

## 5. Edge-Case Coverage Requirements

Every semantic entry must include targeted edge cases.

Minimum edge-case families:

1. Prototype corner cases.
- null-prototype objects, getter/setter exceptions, descriptor redefinition failures.

2. Promise/async ordering races.
- nested `then`, `queueMicrotask`, `await` interleavings with sync throw boundaries.

3. Iterator abrupt completion.
- `break`, `throw`, and `return` paths that should trigger iterator close.

4. Module cycle behavior.
- cycle resolution, partial initialization visibility, and error propagation.

5. Numeric anomalies.
- `-0`, `NaN`, bigint conversion, and overflow-visible paths.

6. Serialization edge behavior.
- non-enumerables, sparse arrays, duplicate object keys, replacer behavior,
  top-level unsupported returns, cycle handling, and key ordering constraints.

7. Security-epoch rollback boundaries.
- future-epoch artifacts, expired windows, inverted windows, stale persisted
  frontiers, and restarts without an authoritative epoch floor.

## 6. test262 And Lockstep Mapping Rules

Each semantic entry must map to:

1. `test262` references.
- one or more concrete `test262` test paths proving baseline behavior.

2. Lockstep fixtures.
- deterministic fixtures run against FrankenEngine and donor lanes with artifact pointers.

3. Waiver governance.
- any mismatch requires explicit waiver with reason, bounded scope, and expiry.

No semantic entry may remain `required` without both `test262_refs` and `lockstep_fixture_refs`.

## 7. Non-Goals (Explicitly Excluded)

The following are intentionally excluded from this semantic spec:

1. donor parser internals and AST implementation details
2. hidden-class or shape implementation choices
3. inline-cache data structures and invalidation strategies
4. optimizer pipeline stage design (for example Turbofan/Ignition composition)
5. donor bytecode formats or opcodes
6. donor GC algorithms and heap layout structures
7. donor object-header memory layout conventions
8. donor-specific scheduler architecture
9. donor-specific JIT heuristics
10. embedding APIs as core execution dependencies (`rusty_v8`, `rquickjs`, equivalents)

These are architecture decisions for FrankenEngine-native synthesis (`bd-2xe`), not semantic requirements.

## 8. Structured Audit Requirements

Semantic extraction, approval, and integration events must emit stable audit keys:
- `trace_id`
- `decision_id`
- `policy_id`
- `component`
- `event`
- `outcome`
- `error_code`

Recommended `component` value: `semantic_donor_spec`.

## 9. Update Workflow

Semantic updates must follow:

1. Collect donor-observable evidence.
2. Normalize into semantic entry schema.
3. Approve under donor extraction governance (`docs/DONOR_EXTRACTION_SCOPE.md`).
4. Integrate entry + conformance artifacts.
5. Update downstream documents (`bd-2xe` architecture synthesis, `bd-j7z` parity tracker).

## 10. Verification Runbook

1. Run semantic donor spec suite:

```bash
./scripts/run_semantic_donor_spec_suite.sh ci
```

2. Inspect generated artifacts:

```bash
ls -la artifacts/semantic_donor_spec/
cat artifacts/semantic_donor_spec/<timestamp>/run_manifest.json
cat artifacts/semantic_donor_spec/<timestamp>/semantic_donor_spec_events.jsonl
```

3. Verify plan linkage:

```bash
rg -n "semantic donor spec document" PLAN_TO_CREATE_FRANKEN_ENGINE.md
```

## 11. Downstream Dependencies

This document is upstream input for:
- `bd-2xe` (FrankenEngine-native architecture synthesis)
- `bd-j7z` (feature-parity tracker with waiver governance)
- VM core workstreams under section `10.2`
