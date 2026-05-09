# RCH Compile Proof Isolation Profile

`scripts/rch_compile_proof_isolation_profile.sh` classifies preserved validation
command metadata into a deterministic proof-isolation profile. It exists so a
future first-error conveyor can tell whether a proof command is narrow enough to
validate the intended change or whether unrelated current-head compile drift
makes the result weak, ambiguous, or fail-closed.

The profiler is advisory-only. It does not run Cargo, invoke `rch`, mutate
`br`, send Agent Mail, edit files, or touch workers.

## Inputs

Required:

- `--metadata-json`: command metadata captured from a preserved validation
  attempt. The profiler accepts common fields such as `command`,
  `validation_command`, `package`, `target`, `test_target`,
  `intended_target_path`, `touched_paths`, `local_fallback_observed`, and
  `transcript_truncated`.

Optional:

- `--changed-paths-json`: either an array of changed paths or an object with
  `changed_paths` or `touched_paths`.
- `--source-revision`: revision to record in emitted artifacts.
- `--case-id`: fixture case identifier.
- `--output-dir`: artifact directory.

## Decisions

- `pass`: evidence is coherent and the command is narrow or shell/json scoped.
- `degraded`: evidence is usable but broad or target-ambiguous.
- `fail_closed`: command metadata is missing, local fallback contamination is
  present, Cargo package targeting is ambiguous, or a broad all-targets command
  is claimed as narrow proof.

## Artifacts

Each run emits:

- `compile_proof_isolation_profile.json`
- `run_manifest.json`
- `events.jsonl`
- `commands.txt`
- `report.md`

The machine-readable contract is
`docs/rch_compile_proof_isolation_profile_contract_v1.json`.

## Smoke Proof

```bash
./scripts/e2e/rch_compile_proof_isolation_profile_smoke.sh check
./scripts/e2e/rch_compile_proof_isolation_profile_smoke.sh selftest
```

The selftest covers:

- a narrow integration-test proof
- a broad lib-test proof with unrelated-drift risk
- a shell-only proof
- local fallback contamination
