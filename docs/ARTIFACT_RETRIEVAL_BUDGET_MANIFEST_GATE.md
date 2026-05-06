# Artifact Retrieval Budget Manifest Gate

`scripts/artifact_retrieval_budget_manifest_gate.sh` is a deterministic shell
gate that proves a remote proof suite retrieves only the minimal artifact set
needed for replay. It compares:

- the suite's published artifact surface
- a declared retrieval-budget manifest
- the actual retrieved file set

This is a fixture-driven checker:

- it does not query live `rch`
- it does not execute Cargo
- it does not fetch files from workers

## Contract

Output schema: `franken-engine.artifact-retrieval-budget-manifest-gate.v1`

Required inputs:

- `--suite-manifest-json`
- `--retrieval-manifest-json`
- `--retrieved-files-json`

Artifacts:

- `artifact_retrieval_budget_verdict.json`
- `artifact_retrieval_budget_summary.md`
- `commands.txt`
- `events.jsonl`

## Decision Rules

The gate passes only when all of these are true:

- every declared retrieval artifact exists in the suite manifest
- every replay-critical artifact was actually retrieved
- the actual retrieved files stay within the declared artifact budget
- neither the declared nor retrieved paths include a broad target-dir or
  wildcard pull such as `target/`, `.rch-target`, `rch_target`, or
  `/tmp/rch_target.../**`

Any violation is fail-closed.

## Operator Flow

Remote proof lanes should retrieve a compact set such as:

- `run_manifest.json`
- `events.jsonl`
- `commands.txt`

They should not retrieve whole worker target directories or other broad path
globs. This gate makes that contract replayable and deterministic.

## Validation

```bash
bash -n scripts/artifact_retrieval_budget_manifest_gate.sh
bash -n scripts/e2e/artifact_retrieval_budget_manifest_gate_smoke.sh
bash scripts/e2e/artifact_retrieval_budget_manifest_gate_smoke.sh check
bash scripts/e2e/artifact_retrieval_budget_manifest_gate_smoke.sh selftest
```
