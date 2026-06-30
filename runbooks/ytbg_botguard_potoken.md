# Runbook: YouTube BotGuard / PO-token JS support (`franken_engine` ↔ `franken_whisper`)

> Capability spine: [`bd-8enww`](../.beads/issues.jsonl) (**YTBG-000**). Doc bead:
> `bd-8enww.5.8` (**YTBG-E8**). Release gate: `bd-8enww.5.7`.
> This runbook is the single source of implementation context for the YTBG tree —
> it is intended to make the original gap-report markdown unnecessary for future
> agents. Everything below is grounded in closed beads and the committed
> tests/scripts; capabilities are marked **Supported**, **Partial**, or **Open**
> honestly, not aspirationally.

## What this is (one paragraph)

`franken_whisper` extracts the frozen JavaScript that YouTube's player and BotGuard
ship (the signature-cipher `s` transform, the `n` throttling transform, and the
BotGuard VM that mints a PO-token). `franken_engine` is the de-novo, Rust-native
runtime that **replays that extracted JavaScript offline** — no network, no browser,
no V8 / QuickJS / boa binding, and no Node or Python JavaScript fallback in the core
path. The YTBG tree (Tracks A–E) built and gated the language surface that this
class of code exercises: typed arrays + `DataView` (BotGuard VM memory), the
`Function` constructor (contained dynamic codegen), `try`/`catch`/`finally` with
catchable native errors, deterministic `Date`/`performance` shims, instruction
budgets with execution logs, and an offline fixture contract for both the
cipher/n-param functions and the PO-token computation. The "done" definition is the
one-command release gate in [`scripts/run_ytbg_release_gate.sh`](../scripts/run_ytbg_release_gate.sh).

## Hard no-go constraints (non-negotiable)

- **No binding-led core execution.** No `rusty_v8` / `rquickjs` / boa / browser /
  Node / Python JavaScript engine on the execution path. `legacy_quickjs/` and
  `legacy_v8/` are reference corpora only.
- **Offline by construction.** Fixtures carry the extracted JS and its source
  hashes; replay never fetches YouTube or invokes `franken_whisper` internals.
- **Deterministic replay.** `Date`/`performance` are deterministic shims; runs are
  byte-reproducible including the consumed-instruction count.

## Support matrix

| Capability | Track / bead | State | Notes |
|---|---|---|---|
| Signature cipher (`s`) transform | A1, A2, A4 (`bd-8enww.1.*`) | Supported | gated in `youtube_botguard_js_conformance` |
| `n` throttling transform | A2, A4 | Supported | same suite |
| `ArrayBuffer` + `byteLength` | B2 (`bd-8enww.2.2`) | Supported | |
| `Uint8Array` / `Int32Array` / `Uint32Array` | B3, B4 | Supported | indexed get/set + numeric coercion |
| TypedArray methods (memory shuffling) | B5 | Supported (high-ROI subset) | not the full TypedArray prototype |
| `DataView` integer accessors | B6 | Supported | over `ArrayBuffer` |
| `Function` constructor parse/compile | C2 (`bd-8enww.3.2`) | Supported | |
| Generated-function invocation + scope | C3 | Supported | resolves realm builtins + **top-level** decls; see `bd-8enww.5.9` |
| Generated-code provenance / budgets / accounting | C4 | Supported | `EvalOutcome.generated_code_audit` |
| `try` / `catch` / `finally` + `throw` | D1, D2, D4 | Supported | finally completion ordering + break/continue forwarders (D4, 4.9) |
| Catchable native `TypeError` / `ReferenceError` | D3 | Supported | module-level TDZ; function-body TDZ is partial |
| `Error` / `TypeError` / `ReferenceError` objects | D5 | Supported | `toString` string coercion |
| Cross-boundary `throw` (generated fn → caller) | 4.7 | Supported | re-raised into caller catch frames |
| Deterministic `Date` / `performance` shims | E3 (`bd-8enww.5.3`) | Supported | **top-level** site only; see `bd-8enww.5.9` |
| `Object` static methods (BotGuard subset) | E2, E4 | Supported (confirmed subset) | only the statics the spike confirmed needed |
| Instruction budgets + execution logs | E5 (`bd-8enww.5.5`) | Supported | `EvalOutcome.instructions_executed`; deterministic `BudgetExhausted` |
| Synthetic BotGuard VM smoke | E1 (`bd-8enww.5.1`) | Supported | committed fixture |
| Offline PO-token fixture integration | E6 (`bd-8enww.5.6`) | Supported | contract + committed synthetic reproducer |
| Final release gate | E7 (`bd-8enww.5.7`) | Supported | `scripts/run_ytbg_release_gate.sh` |

### Known gaps (track these before pointing real fixtures at the engine)

| Gap | Bead | State | Impact / workaround |
|---|---|---|---|
| `new Function(...)` and `performance.now()` resolve **only at top level** — they throw inside a nested function body | `bd-8enww.5.9` | Open (P2) | Real BotGuard is function-wrapped. Workaround in the synthetic fixture: build the generated mixer + read `performance` at top level and capture them in the entrypoint. Fix locus: function-body free-var resolution in `lowering_pipeline.rs`. |
| Explicit `throw` from a legacy array-callback mini-interpreter (`Array.prototype.reduce`/`forEach`/`map`) is caught by the caller but binds the **error object** instead of the original primitive | `bd-8enww.4.8` | Open (P3) | Affects code that throws a primitive from inside a reduce/forEach/map callback and inspects the caught value. |
| IFC keyword labeling: a string or identifier containing `secret` / `token` / `key` / `api_key` / `password` is labeled `Secret` and **fails closed** any flow derived from it | by design | Intentional | Not a bug — it is the information-flow-control guard. Real fixtures whose challenge text contains these substrings must account for it (see Troubleshooting). |
| TDZ tracking is module-level; function-body TDZ is partial | D3 | Partial | `x; let x=1;` is a catchable `ReferenceError` at module level; inside a function body the coverage is narrower. |

## How to validate

One command runs the full YTBG validation matrix and writes a self-describing
artifact bundle:

```bash
scripts/run_ytbg_release_gate.sh ci
```

- Exit `0` = every required lane is green; `3` = a required lane regressed; `2` =
  setup error.
- Artifacts land in `artifacts/ytbg_release_gate/<run_id>/`:
  - `run_manifest.json` — schema `franken-engine.ytbg-release-gate.v1`: run id, git
    commit, toolchain, per-lane verdicts, optional-fixture status, overall outcome,
    artifact `sha256`s.
  - `commands.txt` — every command the gate ran, in order.
  - `vector_results.jsonl` — one JSON record per lane (target, category, required,
    status, passed/failed/ignored counts, duration).
  - `summary.md` — human-readable pass/fail table + optional-fixture note.
  - `logs/<lane>.log` — raw per-lane test output (carries the per-vector JSON reports).
- Reproducibility check (runs the gate twice, asserts an identical verdict):

```bash
scripts/e2e/ytbg_release_gate_replay.sh ci
```

### Environment knobs

- `CARGO_TARGET_DIR` — use a private dir; the shared `target/` is contended.
- `RUSTUP_TOOLCHAIN` — defaults to `nightly-x86_64-unknown-linux-gnu`. Pinning
  avoids a stable-channel auto-update corrupting the toolchain mid-build.
- `YTBG_ARTIFACT_ROOT`, `YTBG_RUN_ID`, `YTBG_JOBS`, `CARGO_BIN` — see the script header.

### Running a single lane

```bash
cargo test -p frankenengine-engine --test youtube_botguard_js_conformance -- --nocapture
```

The lanes: `youtube_botguard_js_conformance`,
`function_constructor_conformance_bd_8enww_3_5`,
`exception_conformance_suite_bd_8enww_4_6`, `exception_semantics_conformance`,
`botguard_synthetic_vm_smoke_bd_8enww_5_1`,
`botguard_instruction_budget_bd_8enww_5_5`,
`botguard_potoken_fixture_bd_8enww_5_6`.

## franken_whisper handoff

### Engine API surface

`franken_whisper` (or any caller) drives replay through `HybridRouter` in the
`frankenengine-engine` crate:

```rust
use frankenengine_engine::HybridRouter;

let mut router = HybridRouter::default();
let outcome = router.eval("<extracted_js>; <entrypoint>(<input>)")?;        // EvalResult<EvalOutcome>
// budgeted variant (BotGuard-scale loops):
let outcome = router.eval_with_instruction_budget(source, 5_000_000)?;
```

`EvalOutcome` (public fields used by the fixtures):

- `value: String` — the stringified return value of the evaluated program.
- `engine: EngineKind`, `route_reason: RouteReason` — which lane ran and why.
- `console_output: Vec<ConsoleEntry>` — captured `console.*`.
- `source_ingestion: SourceIngestionSummary` — parse/lower provenance.
- `generated_code_audit: Vec<GeneratedCodeAuditEntry>` — `Function`-constructor
  provenance + per-call accounting (`bd-8enww.3.4`).
- `instructions_executed: u64` — consumed instruction steps (`bd-8enww.5.5`); the
  budget surfaces a deterministic `BudgetExhausted` fault when exceeded.

The engine evaluates `<extracted_js>; <entrypoint>(<input>)`, where `entrypoint` is
a plain JavaScript identifier and `input` is supplied as a JSON string literal.

### PO-token fixture contract (`bd-8enww.5.6`)

- Env var: `FRANKEN_ENGINE_POTOKEN_FIXTURES` → a JSON file or a directory of `.json` files.
- Schema: `franken-engine.botguard-potoken-fixture.v1`.
- A committed synthetic fixture
  (`crates/franken-engine/tests/fixtures/potoken/synthetic_botguard_potoken_v1.json`)
  always runs so the path is proven even with no supplied fixture; supplied fixtures
  run when present, else a **structured skip** (never a silent pass).

```jsonc
{
  "schema_version": "franken-engine.botguard-potoken-fixture.v1",
  "fixture_id": "potoken-...",
  "fixture_kind": "synthetic_botguard_potoken",   // or a real BotGuard kind
  "source_url": "...base.js or VM source...",
  "source_observed_utc": "2026-06-30T00:00:00Z",
  "source_sha256": "sha256:<hash of the full source>",
  "extracted_js_sha256": "sha256:<hash of extracted_js>",
  "entrypoint": "computePoToken",                 // a plain identifier
  "extracted_js": "var fold = new Function(...); ... function computePoToken(c){ ... }",
  "challenge_input": "the challenge string passed to the entrypoint",
  "deterministic_env": {
    "instruction_budget": 5000000,                // falls back to DEFAULT_POTOKEN_BUDGET
    "performance_base_tick": 0,                    // performance.now() base
    "clock_source": "deterministic_instruction_tick"
  },
  "expected_output": "potoken.v1:...",            // independently computed, not engine-derived
  "notes": "optional context for humans"
}
```

`expected_output` must be computed by an **independent oracle** (the synthetic
fixture's is computed by a Python generator), so a match is a true differential
check. The run log reports the first divergence index on a mismatch.

### YouTube real-JS fixture contract (`bd-8enww.1.3`)

- Env var: `FRANKEN_ENGINE_YOUTUBE_FIXTURES` → a JSON file or a directory.
- Schema: `franken-engine.youtube-real-js-fixture.v1`; `fixture_kind` is
  `signature_cipher` (the `s` transform) or `n_param` (the `n` transform).
- Fields mirror the PO-token contract but the input field is `encrypted_input`; the
  test evaluates `<extracted_js>; <entrypoint>(<encrypted_input as a JSON string>)`.

### Adding a fixture

1. Extract the frozen function(s) from the observed `base.js` / VM source.
2. Compute `source_sha256` (full source) and `extracted_js_sha256` (the
   `extracted_js` string), each `sha256:<hex>`.
3. Choose a plain-identifier `entrypoint` that `extracted_js` defines.
4. Compute `expected_output` with an independent oracle (not this engine).
5. Drop the JSON under your fixtures dir and point the env var at it; run the
   matching lane (or the whole gate). Absent fixtures are reported, not failed.

## Out of scope / deferred JS APIs

- **Anything requiring a real browser DOM / `window` / network** — out of scope by
  design; BotGuard's environment probes are expected to be satisfied by the
  extracted-and-frozen fixture, not by the engine emulating a browser.
- **Full TypedArray/`DataView` prototype** — only the high-ROI subset BotGuard uses
  (`bd-8enww.2.5`/`2.6`) is implemented.
- **Full `Object` / `Date` / `performance` surface** — only the confirmed subset
  (`bd-8enww.5.2`–`5.4`); the shims are deterministic, not wall-clock.
- **`new Function` / `performance` inside nested function bodies** — deferred to
  `bd-8enww.5.9` (top-level only today).
- **Legacy array-callback throw value fidelity** — deferred to `bd-8enww.4.8`.
- **Regex / Proxy / generators / async-await / modules** — not part of the YTBG
  scope; add a new track if a real fixture needs them.

## Troubleshooting — failure → likely track

| Symptom | Likely track / bead | First move |
|---|---|---|
| A cipher / `n`-param vector returns the wrong string | A (`bd-8enww.1.*`) | inspect `logs/cipher_typedarray_function.log`; diff against `expected_output` |
| TypedArray / `DataView` index or coercion is wrong | B (`bd-8enww.2.*`) | check the typed-array conformance vectors in the same lane |
| `new Function(...)` throws "uncaught exception" inside a function | `bd-8enww.5.9` | move the `new Function` to top level and capture it; or push 5.9 |
| `performance` is `undefined` / `performance.now()` throws inside a function | `bd-8enww.5.9` | read `performance` at top level and capture; or push 5.9 |
| An exception is not caught, or `finally` runs in the wrong order | D (`bd-8enww.4.*`) | `exception_semantics_conformance` + `exception_conformance_suite` lanes |
| A caught value is an error object when a primitive was thrown | `bd-8enww.4.8` | only via `reduce`/`forEach`/`map` callbacks today |
| `eval.capability.denied` on a variable or string named `secret`/`token`/`key` | IFC labeling (by design) | rename the binding or avoid the substring in the challenge |
| `BudgetExhausted` on a legitimate long run | `bd-8enww.5.5` | raise `deterministic_env.instruction_budget` in the fixture |
| PO-token digest mismatch | `bd-8enww.5.6` | read the first-divergence index in the run log; re-derive `expected_output` with the oracle |
| The gate exits `3` with a `build_error` lane | toolchain / target | pin `RUSTUP_TOOLCHAIN`, use a private `CARGO_TARGET_DIR`, re-run |

## Appendix: YTBG bead index

- **YTBG-A** (`bd-8enww.1`) — regression/conformance harness: `1.1`–`1.5` (closed).
- **YTBG-B** (`bd-8enww.2`) — typed arrays / `ArrayBuffer` / `DataView`: `2.1`–`2.7` (closed).
- **YTBG-C** (`bd-8enww.3`) — `Function` constructor + contained codegen: `3.1`–`3.5` (closed).
- **YTBG-D** (`bd-8enww.4`) — `try`/`catch`/`finally` + catchable errors: `4.1`–`4.7`, `4.9` (closed); `4.8` (open, P3).
- **YTBG-E** (`bd-8enww.5`) — BotGuard/PO-token integration + gates: `5.1`–`5.7` (closed); `5.8` (this doc); `5.9` (open, P2).
