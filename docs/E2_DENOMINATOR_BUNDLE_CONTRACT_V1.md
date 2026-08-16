# E2 Node/Bun Denominator Reproducibility Bundle (V1)

Operator companion to [`docs/e2_denominator_bundle_contract_v1.json`](./e2_denominator_bundle_contract_v1.json).
Owning bead: **bd-fqlfw.2.6** · Claim: **FE-CLAIM-010** (Node/Bun denominator throughput).

## What this is

The `differential-oracle perf` arm measures warm steady-state throughput of every
corpus case under Node, Bun, and the native engine, and produces a report
(`report.json`). The v3 report records its fresh-engine/shared-realm lifecycle
asymmetry and therefore keeps both denominators degraded; its raw samples and
per-case ratios are diagnostic evidence, not a publishable comparison. This
contract wraps that report in a content-addressed reproducibility bundle so its
evidence can support — or honestly defer — FE-CLAIM-010, instead of living as a
gitignored local artifact.

The committed bundle lives at [`docs/perf/e2_denominator_bundle_v1/`](./perf/e2_denominator_bundle_v1/):

| File | Schema | Role |
|---|---|---|
| `denominator.json` | `franken-engine.e2-denominator-bundle.v1` | Distilled measured denominator + per-case correctness verdicts. |
| `env.json` | `franken-engine.env.v1` | Host / toolchain facts plus recorded resolved Node/Bun versions and paths; nominal manifest pins are not enforced. |
| `repro.lock` | `franken-engine.repro-lock.v1` | Locked replay recipe; expected output is the correctness-verdict hash. |
| `manifest.json` | `franken-engine.manifest.v1` | Content-addressed index referencing the other three by sha256. |
| `degraded_receipt.json` | `franken-engine.e2-denominator-degraded-receipt.v1` | Present **iff** the denominator is degraded/unavailable. |

## Reproducibility scope (the honest part)

Wall-clock timing is inherently non-deterministic, so a perf bundle can never be
byte-identical run-to-run. The reproducibility assertion is therefore scoped to
the **correctness verdicts**: the sorted per-case projection of `case_id`,
`source_sha256`, `behavior_equivalent`, and `equivalence_group`. The corpus
content digest is a separate locked input; it is not part of that projection.
The projection is captured as `correctness_verdict_hash` in `denominator.json`
and locked into `repro.lock.expected_outputs[0].sha256`. The current v3 builder
excludes timing/CV-dependent admission from this hash and retains admission only
under `measurement_evidence`. The committed historical bundle predates that
fix: its verdict vector includes `admitted`, so its hash is not strictly
timing-independent and must not be cited as byte-identical replay proof. A fresh
v3-generated degraded bundle is required to exercise the corrected contract.

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

The committed historical bundle records a materially slower native baseline,
but its lifecycle, source-state, runtime-pin, aggregation, and reproducibility
limitations prevent it from certifying the `>= 3x` throughput floor. A v3
report is deliberately **not evaluable** as a publishable denominator while
the engine uses a fresh core per iteration and Node/Bun reuse a realm and JIT
state. `meets_3x_floor` is therefore null in a newly generated degraded bundle,
and FE-CLAIM-010 stays **TARGET**. The bundle is wired into the claim matrix by
bd-fqlfw.2.7; the matrix gate sees the `repro.lock` partner under the bundle
root, but that structural linkage is not performance certification.

## Version pinning caveat

The corpus manifest (`benchmarks/runtime_comparison/manifest.json`) declares
nominal `runtime_pins` (node 22.13.1, bun 1.1.43). The bundle records the
**actually measured** node/bun versions from the run host (which may differ);
the fairness check guards against `node` resolving to a Bun shim
(`node_genuine`) rather than enforcing exact version equality. Operators
reproducing the number should compare against `env.json.baselines`.
