# RGC Theorem Mining and Law Promotion V1

Primary bead: `bd-1lsy.9.10`

This surface operationalizes the current theorem-mining substrate as a replayable
artifact bundle instead of leaving it as library-only catalog assembly.

## Current Scope

- deterministic candidate-law catalog generation from replayable counterexamples
  and evidence entries
- explicit per-artifact schemas for:
  - `candidate_law_catalog.json`
  - `invariant_seed_ledger.json`
  - `normal_form_hypotheses.json`
  - `law_provenance_index.json`
  - `candidate_scope_hypotheses.json`
- replay triad and operator bundle:
  - `trace_ids.json`
  - `run_manifest.json`
  - `events.jsonl`
  - `commands.txt`
  - `env.json`
  - `manifest.json`
  - `repro.lock`
  - `summary.md`

## Operator Commands

```bash
# rch-backed law-mining suite
./scripts/run_law_mining_suite.sh ci

# deterministic replay wrapper
./scripts/e2e/law_mining_replay.sh ci
```

The suite uses `rch` for the expensive cargo work, then runs the retrieved local
`franken_law_mining` binary to write replay artifacts under
`artifacts/law_mining/<timestamp>/`.

## Binary Surface

```bash
cargo run -p frankenengine-engine --bin franken_law_mining -- \
  --artifact-dir artifacts/law_mining/manual \
  --trace-id trace.rgc.810 \
  --decision-id decision.rgc.810 \
  --policy-id policy.rgc.810 \
  --run-id run-rgc-810-manual \
  --generated-at-utc 2026-03-08T00:00:00Z \
  --source-commit "$(git rev-parse HEAD)" \
  --toolchain nightly \
  --summary
```

The current binary emits a deterministic built-in fixture bundle so the parent
bead has a stable operator and replay surface even before the blocked child
beads (`bd-1lsy.9.10.1` / `bd-1lsy.9.10.2` / `bd-1lsy.9.10.3`) land their full
counterexample-mining, refutation, and promotion logic.
