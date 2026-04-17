# RGC Kernel Synthesis Contract v1

Beads: `bd-1lsy.7.13`, `bd-1lsy.7.13.1`

This contract turns the existing kernel-synthesis eligibility module into a
replayable operator lane. It mines the canonical hot-kernel corpus, classifies
each kernel into eligible/forbidden/deferred buckets, emits the synthesis
evidence manifest, and writes a deterministic artifact bundle that later
superoptimization and translation-validation lanes can consume. The bundle also
emits `superoptimization_report.json`, tying budgeted synthesis sessions,
equivalence receipts, counterexample archives, stale invalidation, and
deterministic rollback semantics to the run manifest.

## Guard Scope

- the corpus is mined from the shipped `kernel_synthesis_contract` baseline and
  must stay deterministic for identical source trees
- the eligibility report must preserve explicit bucket membership for eligible,
  forbidden, and deferred kernels rather than collapsing them into a single
  scalar score
- the evidence bundle must remain fail-closed if required artifacts are missing
  or if the report/manifests drift from the expected schema versions
- all heavy Rust verification for this lane must execute through `rch`

## Required Artifacts

- `commands.txt`
- `env.json`
- `events.jsonl`
- `kernel_schema_catalog.json`
- `kernel_synth_evidence_manifest.json`
- `manifest.json`
- `repro.lock`
- `run_manifest.json`
- `superoptimization_report.json`
- `summary.md`
- `synthesis_eligibility_report.json`
- `trace_ids.json`

## Verification

```bash
./scripts/run_kernel_synthesis_contract_suite.sh ci
./scripts/e2e/kernel_synthesis_contract_replay.sh ci
```

The suite is `rch`-backed, defaults `CARGO_TARGET_DIR` to the stable external
path `/data/tmp/rch_target_franken_engine_kernel_synthesis_contract`, and emits
the bundle under `artifacts/kernel_synthesis_contract/<timestamp>/`.

Override `CARGO_TARGET_DIR=...` only when you need isolated experimentation.
The suite manifest records both `cargo_target_dir` and
`cargo_target_dir_strategy` so timeout/debug traces show whether the run used
the reusable default or an explicit override.
