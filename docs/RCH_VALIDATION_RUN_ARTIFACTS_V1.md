# RCH Validation Run Artifacts V1

`bd-wwfiw` defines a deterministic artifact bundle for RCH validation attempts.
The bundle lets an operator cite a source pass, source failure, remote toolchain
failure, remote timeout, local fallback refusal, or missing remote proof without
rerunning a heavy Cargo command.

The generator is:

```bash
scripts/rch_validation_run_artifacts.sh \
  --output-dir artifacts/rch_validation_runs/example \
  --case-id remote-cargo-check-pass
```

It reads:

- `docs/rch_validation_preflight_contract_v1.json`
- `docs/rch_validation_remote_proof_classifier_v1.json`

It writes these files into the output directory:

- `run_manifest.json`
- `events.jsonl`
- `commands.txt`
- `trace_ids.json`
- `summary.md`

The generator refuses to overwrite existing artifact files. Use a fresh output
directory per run so validation evidence remains append-only.

## Manifest Contract

`run_manifest.json` records:

- selected worker and remote command evidence
- `CARGO_TARGET_DIR` policy and required worker components
- observed verdict, reason code, and source-evidence boolean
- remediation text and a safe rerun command
- parent bead/thread identifiers for Agent Mail and bead closeout

For heavy Cargo lanes, the safe command is always an `rch exec -- ... cargo ...`
command. If the classifier input only preserved a bare local Cargo command, the
manifest marks the run as `missing_remote_proof` and emits a remote-safe rerun
command instead of copying the bare command into `commands.txt`.

## Summary Categories

`summary.md` separates the operator states that have different closeout meaning:

- `source evidence`: remote command completed with exit 0
- `source failure`: remote command completed with a source diagnostic
- `remote toolchain failure`: worker component or toolchain blocked validation
- `remote timeout`: remote command started but no final remote verdict exists
- `local fallback refusal`: local execution was refused after remote failure
- `missing proof`: worker, command, or final remote evidence is absent

Only `source evidence` and `source failure` may be treated as source validation
evidence. All other states are blocker evidence.
