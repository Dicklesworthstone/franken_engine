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

## Validation Recommendations

Each profile also emits `validation_recommendation`, an advisory object with a
kind, command text when safe, rationale, desired-test context, and blocking
diagnostics. Recommendation kinds are:

- `exact_integration_test`: rerun an exact integration test through `rch`.
- `exact_lib_test_filter`: use a named lib-test filter through `rch` instead of
  a full lib or all-targets proof.
- `no_run_compile`: use an `rch` no-run compile when Rust paths need compile
  proof but no exact test is known.
- `shell_golden_only`: use shell, JSON, or golden-file proof for non-Rust
  artifact changes.
- `blocked_no_safe_proof`: refuse to recommend a source-fix proof until cleaner
  metadata exists.

Rust validation recommendations always preserve an `rch exec --` command shape;
the profiler never suggests bare local Cargo.

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
- an exact lib-test filter recommendation
- a no-run compile recommendation
