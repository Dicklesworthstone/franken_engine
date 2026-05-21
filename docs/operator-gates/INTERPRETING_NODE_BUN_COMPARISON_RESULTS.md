# Interpreting Node / Bun Comparison Results

Operator runbook for reading the **S_B** (Score-vs-Baseline) outputs of
the FrankenEngine benchmark publication gate against Node and Bun, for
understanding when a workload is quarantined from the denominator, and
for proposing a new workload class with weights.

## Bead anchors

- Track parent: **bd-cixqu.5** (FE-CLAIM-010 — Node + Bun denominator
  throughput ≥3× weighted geometric mean).
- This document: **bd-cixqu.5.8** (E.8 operator-runbook).
- Underlying code: `crates/franken-engine/src/benchmark_denominator.rs`
  (deterministic weighted-geometric-mean scoring + publication gate).
- Threshold constant: `SCORE_THRESHOLD = 3.0` (line 13 of that module).
- Error catalogue: `FE-BENCH-1001 … FE-BENCH-1007`.

## What S_B is

The publication gate produces two scalars per run, both fixed-point
weighted geometric means of per-workload speedups:

| Field | Meaning |
|---|---|
| `score_vs_node` | S_B against Node. The weighted geometric mean of `throughput_franken_tps / throughput_baseline_tps` over admitted Node-baseline cases. |
| `score_vs_bun` | S_B against Bun. Same shape, Bun baseline. |
| `publish_allowed` | `true` only when BOTH scores are `>= SCORE_THRESHOLD` (3.0) AND no `blockers` were emitted. |
| `blockers` | A list of stable error codes (`FE-BENCH-1xxx`) explaining why publication was refused. |

Read both scores together. A run that passes against Node but fails
against Bun is **not** publishable under FE-CLAIM-010 — the claim is
against both baselines, not the better of the two.

The scoring is computed via `weighted_geometric_mean()` in
`benchmark_denominator.rs:183`. The geometric mean is taken in log-space
with a fixed-point round at `ROUND_SCALE = 1e12` to keep the published
number cross-platform bit-stable.

## Field reading order for a PublicationGateDecision

When you receive a `PublicationGateDecision` (the structured output of
`frankenctl benchmark score`), read its fields in this order:

1. **`publish_allowed`** — the one-bit verdict. `true` means the bundle
   passes the publication gate; `false` means at least one constraint
   was violated. If `true`, the remaining fields are still worth
   reading for posture, but no immediate action is required.
2. **`blockers`** — non-empty iff `publish_allowed == false`. Each
   entry is one of the `FE-BENCH-1xxx` codes:

   | Code | Meaning | Typical fix |
   |---|---|---|
   | `FE-BENCH-1001` | Invalid case set (empty, duplicate workload_ids, …). | Rebuild the case set; check for duplicate workload_ids. |
   | `FE-BENCH-1002` | Invalid weight (negative, NaN, zero where required). | Audit per-case `weight` fields. |
   | `FE-BENCH-1003` | Invalid throughput (non-positive, NaN, ∞). | Re-collect throughput samples; check the harness measurement window. |
   | `FE-BENCH-1004` | Weight sum violates `WEIGHT_SUM_EPSILON` (1e-9). | Normalise weights to sum to 1.0 within ±1e-9. |
   | `FE-BENCH-1005` | Native-coverage progression incomplete. | Add the missing `NativeCoveragePoint` entries until the progression covers the run window. |
   | `FE-BENCH-1006` | Missing replacement-lineage id. | Wire `replacement_lineage_ids` to the lineage ledger entries; cross-check with `bd-cixqu.12.1`. |
   | `FE-BENCH-1007` | Score below threshold OR coverage / lineage envelope insufficient. | Investigate which baseline scored under 3.0; the per-baseline score is in the same decision. |
3. **`score_vs_node`** — interpret literally: 3.0 means FrankenEngine is
   3× the geometric-mean speedup against Node across admitted
   workloads. Below 3.0 is a publication-blocking gap. The detailed
   per-case speedups live in `events.jsonl`.
4. **`score_vs_bun`** — same shape, Bun.
5. **`native_coverage_progression`** — the time-stamped coverage curve
   echoed back so a future replay can reconstruct exactly what the gate
   saw. Each `NativeCoveragePoint` has `recorded_at_utc`, `native_slots`,
   `total_slots`. The gate refuses to publish if the progression does
   not cover the run window.

## When a workload is quarantined from the denominator

A `BenchmarkCase` is admitted into the geometric mean **only** when all
of the following per-case flags are `true`:

| Flag | What it asserts |
|---|---|
| `behavior_equivalent` | FrankenEngine produced the same observable behaviour as the baseline runtime (same return values, same console output, same exceptions). |
| `latency_envelope_ok` | The per-iteration latency stayed inside the declared envelope. |
| `error_envelope_ok` | No error count outside the declared envelope. |
| `execution_authentic` | The execution used the real engine path (no `MockCertificate`, no `hot_paths_simulation`, no fixture passing as data — per the README "Test & Mock Discipline" rule). |

A case with any of those flags `false` is **quarantined** from the
score: its speedup is excluded from the geometric mean. The case still
appears in `events.jsonl` so the audit trail is complete, but it does
not contribute to `score_vs_node` or `score_vs_bun`.

Operator interpretation:

- A quarantined workload is **not a publication failure on its own**.
  The gate's verdict depends on the admitted set, not the total set.
- But: a workload that should be admitted yet was quarantined is a
  signal. Walk through the flag table above and identify which envelope
  failed. Most operational quarantines come from `latency_envelope_ok`
  (workload tail latency exceeded the declared bound) or
  `behavior_equivalent` (a divergence in observable output).
- A run where >25% of cases are quarantined is a red flag even if the
  remaining cases score over 3.0. The denominator is no longer
  representative of the workload distribution. Escalate to the
  benchmark owner for a re-measurement.

## Proposing a new workload class with weights

Adding a new workload class to the denominator is a deliberate act — it
changes the population the published claim is averaged over. Follow
this sequence:

### Step 1 — Confirm the workload class is in scope

The denominator claim (FE-CLAIM-010) is about "real workloads operators
care about", not micro-benchmarks. Before proposing a class, confirm:

- The workload is reachable from `frankenctl run` and `frankenctl
  benchmark` without manual instrumentation.
- The workload is reproducible byte-identically given a fixed seed and
  fixed inputs (so replay can verify it).
- The workload exercises a code path that is not already represented
  by another admitted class (no double-counting).
- A baseline implementation exists in both Node and Bun. The claim is
  comparative; a workload that runs only in FrankenEngine cannot be
  scored against either baseline and must be proposed under a
  different claim.

### Step 2 — Pick a weight

Weights are positive floats that sum to 1.0 across the admitted set
(within `WEIGHT_SUM_EPSILON = 1e-9`). Pick a weight that reflects the
workload's relative importance to the deployment lane. Conventions:

| Weight | Class character |
|---|---|
| `0.05 – 0.10` | A representative but minor workload; exercises a code path but is not on the critical path. |
| `0.10 – 0.25` | A meaningful class on a typical deployment lane. |
| `> 0.25` | A dominant class. Use sparingly — the geometric mean becomes brittle when one class carries most of the weight. |

If you do not pass a weight on a `BenchmarkCase`, the case enters with
an equal-weight default and the other weights are renormalised. Mixing
explicit and implicit weights in the same case set is permitted but
makes the intent harder to audit; prefer explicit weights for every
admitted case.

### Step 3 — Implement the workload + manifest

The workload itself is a JavaScript or TypeScript program under
`crates/franken-engine/benches/<workload_class>/`. The manifest is a
JSON record that names the workload, declares its weight, and points at
the baseline implementations. Cross-check the existing entries for
shape — do not invent a new schema.

### Step 4 — Local dry-run

```bash
frankenctl benchmark score \
    --input <publication_gate_input.json> \
    --output <results.json>
```

Inspect `results.json`:

- `publish_allowed` should be `true` (the new workload's per-case
  speedup is above whatever the existing set averages to, AND no
  envelope flags fired against it).
- `score_vs_node` and `score_vs_bun` should both stay above
  `SCORE_THRESHOLD`.
- `blockers` should be empty.

If the score drops below 3.0 against either baseline, the proposed
workload class is exposing a real gap. Do NOT widen the workload
definition to artificially raise its measured speedup — the claim is
about real-workload coverage. File the gap as a bead instead.

### Step 5 — Submit for review

The new workload class needs sign-off from the benchmark owner and the
claim-publisher (the matrix gate refuses promotion-language changes
without artifact backing). Attach:

- The new `BenchmarkCase` manifest entry.
- The `publication_gate_input.json` used in the dry-run.
- The `results.json` showing `publish_allowed: true`.
- The replay command from `commands.txt` so a reviewer can reproduce.

### Step 6 — Land + re-publish

After the workload class is admitted, every subsequent publication run
uses the new weight set. If you need to retire a class, leave it in
the manifest with `weight: 0.0` (legal under the gate) for one release
cycle so the matrix can record the transition, then remove it in the
next cycle.

## Related operator surfaces

- [`RGC_GATES_REFERENCE.md`](./RGC_GATES_REFERENCE.md) — the broader RGC
  gate catalogue.
- [`ADDING_A_NEW_CAPABILITY.md`](./ADDING_A_NEW_CAPABILITY.md) — the
  shape of an extension-author-side workflow (bd-cixqu.3.7); mirrors
  this document's Step 1-6 pattern.
- [`docs/CLAIM_TO_PROOF_MATRIX_V1.md`](../CLAIM_TO_PROOF_MATRIX_V1.md) —
  the source of truth for FE-CLAIM-010's wording state. The matrix gate
  refuses claim-language changes whose backing artifact has not
  matured.
- `crates/franken-engine/src/benchmark_denominator.rs` — the scoring
  module itself. The test module at the bottom of that file is the
  ground truth for the gate's behaviour across edge cases (empty case
  set, weight sum drift, NaN throughput, etc.).
