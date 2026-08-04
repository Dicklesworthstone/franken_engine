# DW Testing & Verification Standard (bd-fqlfw.11 / DW.STD)

> The shared, mandatory verification contract for every Dueling-Wizards capability
> (`bd-fqlfw.*`). Every `E*.TEST` capstone references this document; it need only name
> what is *specific* to its capability — the layers below are mandatory for all of them.
>
> **Why this exists.** For a runtime whose brand is "claims cannot exceed evidence," an
> unverified feature is an unshippable feature. This standard encodes the repo's existing
> gate / signed-artifact / replay culture so new capabilities match it exactly, and ships
> the reusable machinery so meeting it is cheap.

## Shipped machinery (use it; do not reinvent)

| Artifact | Purpose |
|---|---|
| [`scripts/dw/lib/dw_e2e_lib.sh`](../../scripts/dw/lib/dw_e2e_lib.sh) | Shared bash harness: structured `events.jsonl` logging, `run_manifest.json` with sha256 content hashes, degraded-receipt emission, per-step capture, fail-closed exit codes. |
| [`scripts/dw/templates/run_dw_capability.sh.template`](../../scripts/dw/templates/run_dw_capability.sh.template) | Copy → `scripts/run_dw_<cap>.sh`. The e2e gate skeleton (modes `check\|test\|clippy\|ci`). |
| [`scripts/dw/templates/dw_capability_replay.sh.template`](../../scripts/dw/templates/dw_capability_replay.sh.template) | Copy → `scripts/e2e/dw_<cap>_replay.sh`. Re-verifies a preserved bundle (content-hash integrity + pass-outcome) and detects tampering. |

The harness is self-verified: the smoke run proves a pass bundle certifies via the replay
wrapper (exit 0) and that a one-byte mutation of `events.jsonl` is caught as a content-hash
mismatch (exit 1). Exit codes: **0 = pass, non-zero = fail-closed, 3 = degraded** (a required
dependency such as `node`/`bun`/a solver/the Lean toolchain was unavailable — emits
`degraded_receipt.json`, **never a silent pass**).

## Mandatory test layers (every capability)

1. **Unit tests** (`cargo test`, alongside changed logic): happy path, *every* fail-closed
   branch, edge cases, and ≥1 adversarial/negative case. Deterministic, replay-friendly
   fixtures (no wall-clock, no rng, no `HashMap`-order dependence). Name the module under test.
2. **Integration tests** (`crates/franken-engine/tests/`): exercise the real public surface
   end-to-end. No mocks standing in for the engine; mocks only for external services, and
   even then prefer real subprocesses.
3. **E2E gate script** `scripts/run_dw_<cap>.sh ci`: drives the full capability and emits an
   artifact bundle `artifacts/<cap>/<timestamp>/` containing a signed-able `run_manifest.json`
   (schema id + source revision + host facts + content hashes + verify command), a structured
   `events.jsonl` (the detailed log — one line per step with input/output hashes, decision,
   timing), `commands.txt`, and `steps/<n>_<slug>.log`. Built on `dw_e2e_lib.sh`.
4. **Replay wrapper** `scripts/e2e/dw_<cap>_replay.sh`: re-verifies a preserved bundle and
   asserts integrity (and byte-identical reproduction where the artifact is replayable).
5. **Golden / snapshot** coverage for any stable serialized output (`insta` snapshots or
   golden files), regenerated only via the documented `UPDATE_GOLDENS` path, reviewed as additive.
6. **Fuzzing** (`cargo-fuzz`): any capability touching parsing, lowering, output
   canonicalization, codegen, or external-input deserialization adds/extends a fuzz target
   (E1 spans, E2 canonicalization, E4 codegen inputs, E8 contract parser). Prefer
   **differential** fuzzing where two impls must agree (engine ↔ franken-core) and
   structure-aware fuzzing for the parser. A crash is a fail-closed defect with a minimized
   regression fixture checked in.

## Detailed-logging contract

Every step logs what it received (with input hashes), what it decided + why, what it emitted
(with output hashes), and timing — machine form `events.jsonl`, human form per-step logs +
stderr breadcrumbs. On failure the log is **self-diagnosing** (which input, which invariant,
expected-vs-actual): an operator or agent never re-instruments to understand a failure.

## Observability (operational, distinct from test logging)

Where a capability makes a security decision, emit the existing `runtime_observability`
security counters (`capability_denial` / `auth_failure` / `replay_drop` / `cross_zone` /
`revocation_check` / `checkpoint_violation`) at the real call site — never silently drop a
telemetry error (the `bd-z8w7k` anti-pattern); bounded log buffers (no unbounded growth — the
`bd-rcrlc` anti-pattern).

## Determinism / numeric discipline (any hashed or serialized output)

`BTreeMap`/`BTreeSet` (never `HashMap`) where iteration order touches a hash/serde output;
fixed-point millionths (`1_000_000 = 1.0`), never `f64`, in hashed positions; length-prefix
variable-length fields before mixing into a content hash; sort collections before hashing
(`LC_ALL=C`); saturating/wrapping counters; Ed25519 signing via the canonical
`signature_preimage` path.

## CLI ergonomics (every new `frankenctl` surface)

`--json` + an agent robot mode (stable, parseable line protocol), documented stable exit
codes, structured actionable errors (what failed, why, how to fix), `--help` with runnable
examples. The AI-coding-agent is a first-class user; the surface must be loopable.

## Claim discipline

Any wording that reads as OBSERVED registers a row in `docs/claim_to_proof_matrix_v1.json`
with a `repro.lock` partner and passes `run_claim_to_proof_matrix_gate.sh ci`; wording stays
bounded ("inferred … for supported syntax", not absolute). New gates wire into the relevant
truth gate. When a claim reaches OBSERVED, register it in `acceptance_ledger` /
`ga_exit_evidence_package` so it counts toward GA exit.

## Documentation

Every user-facing capability also satisfies **DW.DOCS** (`bd-fqlfw.12`).

## Gate hygiene (every bead's done-state)

`cargo check --all-targets`, `cargo clippy --all-targets -- -D warnings`, `cargo fmt --check`
all green.

## Parking-lot note

Each `E10` item, when promoted, MUST add its own `E*.TEST` capstone meeting this standard
before it can close.
