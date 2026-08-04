# E2 Node/Bun Denominator Reproducibility Bundle (V1)

Operator companion to [`docs/e2_denominator_bundle_contract_v1.json`](./e2_denominator_bundle_contract_v1.json).
Owning bead: **bd-fqlfw.2.6** · Claim: **FE-CLAIM-010** (Node/Bun denominator throughput).

## What this is

The `differential-oracle perf` arm measures warm steady-state throughput of every
corpus case under Node, Bun, and the native engine, and produces a denominator
(`report.json`). This contract wraps that measured denominator in a
content-addressed reproducibility bundle so the number can back — or honestly
fail to back — FE-CLAIM-010, instead of living as a gitignored local artifact.

The committed bundle lives at [`docs/perf/e2_denominator_bundle_v1/`](./perf/e2_denominator_bundle_v1/):

| File | Schema | Role |
|---|---|---|
| `denominator.json` | `franken-engine.e2-denominator-bundle.v1` | Distilled measured denominator + per-case correctness verdicts. |
| `env.json` | `franken-engine.env.v1` | Host / toolchain / runtime facts with **pinned node + bun versions**. |
| `repro.lock` | `franken-engine.repro-lock.v1` | Locked replay recipe; expected output is the correctness-verdict hash. |
| `manifest.json` | `franken-engine.manifest.v1` | Content-addressed index referencing the other three by sha256. |
| `degraded_receipt.json` | `franken-engine.e2-denominator-degraded-receipt.v1` | Present **iff** the denominator is degraded/unavailable. |

## Reproducibility scope (the honest part)

Wall-clock timing is inherently non-deterministic, so a perf bundle can never be
byte-identical run-to-run. The reproducibility assertion is therefore scoped to
the **correctness verdicts**: for each corpus case, whether Node/Bun/engine landed
in the same structured-value equivalence group, plus the corpus content hash.
That projection is captured as `correctness_verdict_hash` in `denominator.json`
and locked into `repro.lock.expected_outputs[0].sha256`. A re-run on the same
host reproduces that hash exactly (bd-fqlfw.2.6 acceptance: *"re-running on the
same host reproduces byte-identical correctness verdicts"*).

## Freshness gate (stale denominators are rejected)

Freshness is enforced two ways:

1. **In the gate (`ci` mode):** the denominator's `generated_unix_ns` must be
   within `E2_DENOM_MAX_AGE_DAYS` (default 90) and the measurement must meet the
   sample floor (`measured_iterations >= 10`, the
   `DEFAULT_MIN_ACQUISITION_SAMPLES` from `benchmark_freshness_gate.rs`). A stale
   or under-sampled denominator fails closed with `FE-REPRO-0007`.
2. **In the test suite:** [`tests/e2_denominator_freshness_integration.rs`](../crates/franken-engine/tests/e2_denominator_freshness_integration.rs)
   drives the real `benchmark_freshness_gate::FreshnessGate`: a fresh denominator
   is full-confidence and rollout-permitted; an under-sampled or drifted one is
   downgraded with rollout blocked; and the committed bundle is asserted to clear
   the sample floor.

## Running it

```bash
# Validate the committed bundle (fail-closed), emit an artifact bundle.
./scripts/run_e2_denominator_bundle_gate.sh ci

# Regenerate the bundle from a fresh measurement (needs genuine node + bun).
E2_DENOM_NODE_BIN=/usr/bin/node E2_DENOM_BUN_BIN="$(command -v bun)" \
  ./scripts/run_e2_denominator_bundle_gate.sh generate

# Replay the latest preserved verdict.
./scripts/e2e/e2_denominator_bundle_replay.sh
```

When node/bun (or the `frankenctl` binary) are unavailable, `generate` writes a
documented `degraded_receipt.json` (`FE-REPRO-0007`) instead of silently passing.
The wall-clock cost of a full run is dominated by the engine lane (a baseline
interpreter is far slower than V8/JSC JIT); `--samples 10` is the practical
fairness floor.

## Degraded policy

Per [`docs/REPRODUCIBILITY_CONTRACT.md`](./REPRODUCIBILITY_CONTRACT.md), degraded
mode must never promote claim status to `observed`. A degraded bundle keeps
FE-CLAIM-010 at `target` and surfaces the reason rather than emitting a number.

## FE-CLAIM-010 linkage

The measured denominator does **not** meet the `>= 3x` throughput floor: the
native baseline interpreter is materially slower than Node's V8 and Bun's JSC
JIT on the corpus. `meets_3x_floor` is therefore `false` for both baselines, and
FE-CLAIM-010 stays **TARGET** — now backed by real, fairness-compliant numbers
rather than absence of data. The bundle is wired into the claim matrix by
bd-fqlfw.2.7; the matrix gate sees the `repro.lock` partner under the bundle
root.

## Version pinning caveat

The corpus manifest (`benchmarks/runtime_comparison/manifest.json`) declares
nominal `runtime_pins` (node 22.13.1, bun 1.1.43). The bundle records the
**actually measured** node/bun versions from the run host (which may differ);
the fairness check guards against `node` resolving to a Bun shim
(`node_genuine`) rather than enforcing exact version equality. Operators
reproducing the number should compare against `env.json.baselines`.
