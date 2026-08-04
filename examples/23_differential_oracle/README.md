# 23 — Differential Oracle (cross-runtime equivalence)

Runs a tiny JavaScript corpus through the **differential oracle**: the same
program is evaluated by multiple backends — the native `franken-engine` lane, the
extracted `franken-core` lane, and (when present) reference runtimes Node and Bun
— and any disagreement is canonicalized and classified.

```bash
./examples/23_differential_oracle/demo.sh
```

The demo:

1. Runs each `corpus/*.js` case across the two **hermetic in-process lanes**
   (`--engines franken,core`), emitting a content-addressed bundle
   (`manifest.json` + `report.json` + `repro.lock`) per case under `out/<case>/`.
2. Re-verifies each bundle **byte-identically** with `frankenctl oracle report`
   (`integrity = verified`).
3. Demonstrates the fail-closed **DEGRADED path**: requesting a reference runtime
   that is not installed (`--engines franken,node` with a non-existent
   `--node-bin`) yields a `degraded_receipt.json` (`FE-REPRO-0007`) and a non-zero
   exit — never a silent pass.

No Node/Bun is required: the consensus corpus uses the in-process lanes, and the
degraded demonstration points `--node-bin` at a deliberately-missing binary.

### Prerequisite

Build `frankenctl` first (the demo auto-discovers `target/release/frankenctl`,
`target/debug/frankenctl`, or `$FRANKENCTL_BIN`):

```bash
cargo build --release -p frankenengine-engine --bin frankenctl
```

### Reading the output

| Field | Meaning |
|---|---|
| `verdict=consensus` (exit 0) | all applicable lanes agree on the semantic value/exception class |
| `verdict=divergence` (exit 3) | a classified semantic divergence was found (see `report.json`'s `divergence_taxonomy`) |
| `verdict=insufficient_data` (exit 4) | fewer than two applicable lanes reached a comparable verdict |
| `degraded=true` (exit 4) | a requested reference runtime was unavailable; see `out/degraded/degraded_receipt.json` |

Inspect a reproduction lock with `jq . out/arith_sum/repro.lock` — note that the
reproducible assertion is the **semantic verdict**, not wall-clock timing.

### See also

- Operator runbook + divergence taxonomy: [`docs/DW_DIFFERENTIAL_ORACLE_V1.md`](../../docs/DW_DIFFERENTIAL_ORACLE_V1.md)
- Gate contract: [`docs/dw_differential_oracle_v1.json`](../../docs/dw_differential_oracle_v1.json)
- Capstone gate: `./scripts/run_dw_differential_oracle.sh ci`
- Node/Bun denominator posture (FE-CLAIM-010): [`docs/perf/e2_denominator_bundle_v1`](../../docs/perf/e2_denominator_bundle_v1)
