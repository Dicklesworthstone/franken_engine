# FE-CLAIM-010 Matrix-Promotion Decision (E.6)

Operator record for the **FE-CLAIM-010** matrix-promotion gate — the
single fail-closed checkpoint that decides whether the `>= 3x weighted
geometric-mean throughput versus Node and Bun` claim may sit at
`observed` in the claim-to-proof matrix.

## Bead anchors

- This decision: **bd-cixqu.5.6** (E.6 — matrix promotion FE-CLAIM-010
  `TARGETED -> OBSERVED`, engineering-gated on `>= 3.0`).
- Track parent: **bd-cixqu.5** (FE-CLAIM-010).
- Upstream evidence: E.1/E.2 Node 22 + Bun 1.x lanes, E.3 cross-runtime
  output equivalence, E.4 `benchmark_denominator.rs` `>= 3.0` scoring,
  E.5 reproducibility bundles. All CLOSED.
- Scoring contract: `docs/benchmark_denominator_weights_v1.json`
  (`gate.threshold = 3.0`, `gate.comparator = ">="`, both baselines).
- Scoring code: `crates/franken-engine/src/benchmark_denominator.rs`
  (`SCORE_THRESHOLD = 3.0`, `evaluate_publication_gate_with_contract`).
- Reading the scores: `INTERPRETING_NODE_BUN_COMPARISON_RESULTS.md`.

## The promotion rule

The matrix entry for FE-CLAIM-010 may only read `observed` when a FRESH,
re-runnable Node/Bun denominator artifact demonstrates:

1. `score_vs_node >= 3.0` **and** `score_vs_bun >= 3.0` — the claim is
   against **both** baselines, never the better of the two; and
2. `publish_allowed == true` (no `FE-BENCH-1xxx` blockers); and
3. a `repro.lock` accompanies the score artifact so a third party can
   reconstruct the measurement.

If any condition fails, the honest outcome is that FE-CLAIM-010 **stays
`target`**. Per the bead: _"Only if the live S_B clears 3.0. If
engineering doesn't deliver that number, the matrix stays TARGETED —
that's the honest outcome and is preferable to fudging."_

## Current decision: STAY_TARGET

As of this gate, **no live Node/Bun denominator artifact clears the
`>= 3.0` threshold**. The publication-gate scoring machinery (E.4) and
the typed workload-class weight contract exist, but
`artifacts/benchmark_denominator/` carries no `PublicationGateDecision`
with a measured `score_vs_node`/`score_vs_bun` at or above 3.0.

The only measured cross-runtime throughput evidence in tree is the
throughput **disruptive-floor** metric input
(`tests/fixtures/throughput_disruptive_floor_metric_input_v1.json`),
which protects against regression below a `0.95x` floor and records
FrankenEngine at roughly **parity** with Node and Bun (per-scenario
ratios ≈ 0.95x–1.09x). That is a different, lower bar than the `>= 3.0x`
publication claim and does **not** support promotion.

Therefore FE-CLAIM-010 correctly remains at `target`, and the gate exits
`0` because the matrix state (`target`) is consistent with the live S_B
evidence.

## Running the gate

```bash
# Evaluate the live tree and emit a decision artifact.
./scripts/run_fe_claim_010_promotion_gate.sh ci

# Prove every decision path (clears / parity / fudge / no-repro-lock)
# without needing the Rust crate to link.
./scripts/run_fe_claim_010_promotion_gate.sh selftest

# Validate a previously emitted decision artifact.
./scripts/run_fe_claim_010_promotion_gate.sh verify <artifact.json>

# Full smoke (check + selftest + live consistency).
./scripts/e2e/fe_claim_010_promotion_gate_smoke.sh run
```

### Inputs (environment overrides)

| Variable | Default | Meaning |
|---|---|---|
| `CLAIM_TO_PROOF_MATRIX_PATH` | `docs/claim_to_proof_matrix_v1.json` | Matrix to read FE-CLAIM-010 state from. |
| `FE_CLAIM_010_WEIGHTS_PATH` | `docs/benchmark_denominator_weights_v1.json` | Threshold + comparator source. |
| `FE_CLAIM_010_SCORE_PATH` | _(auto-discovered)_ | A `PublicationGateDecision` JSON to score. |
| `FE_CLAIM_010_SCORE_SEARCH_ROOT` | `artifacts/benchmark_denominator` | Where to auto-discover a score artifact. |
| `FE_CLAIM_010_PROMOTION_ARTIFACT_ROOT` | `artifacts/fe_claim_010_promotion` | Decision-artifact output root. |

## Fail-closed behaviour

The gate is bidirectional but conservative:

- **Over-claim → hard fail (exit 1).** If the matrix reads `observed`
  while the live S_B does not clear 3.0 (or the score has no
  `repro.lock`), the gate emits the stable code
  `FeClaim010PromotionError::ObservedWithoutClearedThreshold` (or
  `…::ObservedWithoutReproLock`) and fails. This is the anti-fudging
  guard the GA-exit bundle (bd-cixqu.47) depends on.
- **Under-claim → advisory (exit 0).** If a cleared, reproducible score
  exists but the matrix still reads `target`, the gate passes with an
  advisory recommending promotion. Claiming less than the evidence
  supports is never a gate failure.

## When the number finally lands

To promote FE-CLAIM-010 to `observed`:

1. Produce a fresh `PublicationGateDecision` artifact (via
   `frankenctl benchmark score` over the contract weights) with
   `score_vs_node >= 3.0`, `score_vs_bun >= 3.0`, `publish_allowed: true`,
   plus a `repro.lock`.
2. Re-run `./scripts/run_fe_claim_010_promotion_gate.sh ci` and confirm
   the decision flips to `PROMOTE_TO_OBSERVED`.
3. Edit the FE-CLAIM-010 matrix entry to `observed`, point its
   `artifact_path` at the score bundle, set a numeric
   `freshness_days <= 30`, and re-run this gate plus
   `scripts/run_claim_to_proof_matrix_gate.sh` until both are green.
