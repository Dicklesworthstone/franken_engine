# RCH Validation Run Artifacts V1

`bd-wwfiw` defines a deterministic artifact bundle for RCH validation attempts.
The bundle lets an operator cite a source pass, source failure, remote toolchain
failure, remote timeout, pre-admission refusal, local fallback refusal, or
missing remote proof without rerunning a heavy Cargo command.

The generator is:

```bash
scripts/rch_validation_run_artifacts.sh \
  --output-dir artifacts/rch_validation_runs/example \
  --case-id remote-cargo-check-pass
```

It reads:

- `docs/rch_validation_preflight_contract_v1.json`
- `docs/rch_validation_remote_proof_classifier_v1.json`

For a command that never reached worker admission, generate the companion
admission-refusal receipt first:

```bash
scripts/rch_admission_refusal_receipt.sh \
  --diagnose-json artifacts/rch_validation_runs/example/diagnose.json \
  --output-dir artifacts/rch_validation_runs/example \
  --bead-id bd-example \
  --parent-bead-id bd-parent
```

That companion reads saved `rch diagnose --dry-run --json` output only. It does
not run Cargo, call live `rch`, mutate workers, or replace
`run_manifest.json`.

It writes these files into the output directory:

- `run_manifest.json`
- `events.jsonl`
- `commands.txt`
- `trace_ids.json`
- `summary.md`

The admission-refusal companion writes:

- `rch_admission_refusal_receipt.json`
- `events.jsonl`
- `commands.txt`
- `report.md`

The generator refuses to overwrite existing artifact files. Use a fresh output
directory per run so validation evidence remains append-only.

## Manifest Contract

`run_manifest.json` records:

- selected worker and remote command evidence
- stable validation id and command kind
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
- `admission refused before worker start`: `rch diagnose --dry-run --json`
  reported `would_intercept=true` and `would_offload=false`; no worker was
  admitted and Cargo did not execute

Only `source evidence` and `source failure` may be treated as source validation
evidence. All other states are blocker evidence.

## Admission-Refusal Bridge

Use `rch_admission_refusal_receipt.json` when the saved dry-run JSON reports
`final_verdict=admission_refused` and `reason_code=no_admissible_workers`.
Closeout must cite the pending safe `command=rch exec -- ...` from the receipt
as the command to retry later, not as an observed source-verdict command.

Operator categories map to first actions:

- `wait_for_active_project`: wait for the active same-project build to finish,
  then rerun `rch diagnose --dry-run --json` before launching `rch exec --`.
- `worker_health_or_capacity`: wait for worker health or pressure to recover,
  or route to a healthy worker; avoid repeated immediate retries.
- `worker_preflight_or_toolchain`: repair owned toolchain/preflight blockers or
  escalate to the RCH operator before retrying.
- `mixed_no_admissible_workers`: preserve the receipt, avoid local Cargo
  fallback, wait for active-project/pressure recovery, and repair hard-preflight
  blockers if owned.
- `admissible`: do not use admission-refusal closeout; proceed to the normal
  remote `rch exec -- ... cargo ...` validation path.

## Replay Gate

The smoke gate supports:

```bash
scripts/e2e/rch_validation_run_artifacts_smoke.sh check
scripts/e2e/rch_validation_run_artifacts_smoke.sh selftest
scripts/e2e/rch_validation_run_artifacts_smoke.sh replay artifacts/rch_validation_runs/example
```

Replay mode validates a preserved bundle without running live heavy Cargo
commands. It fails closed when any required artifact is missing, when
`events.jsonl` lacks `trace_id`, `validation_id`, `worker_id`, `command_kind`,
`verdict`, `reason_code`, or `remediation`, or when `commands.txt` contains a
heavy Cargo command that is not prefixed with `rch exec --`.
