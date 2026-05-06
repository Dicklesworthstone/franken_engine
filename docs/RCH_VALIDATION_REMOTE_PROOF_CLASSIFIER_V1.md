# RCH Validation Remote-Proof Classifier V1

`bd-bpoi9` defines deterministic fixture classification for preserved `rch`
validation logs. The classifier answers one question: did the validation command
produce source evidence, or did it stop at an infrastructure/toolchain proof
boundary?

The machine-readable fixture is
[`docs/rch_validation_remote_proof_classifier_v1.json`](./rch_validation_remote_proof_classifier_v1.json).
It is intentionally fixture-driven and does not execute live Cargo commands.

## Verdicts

- `source_pass`: remote command completed successfully and can be cited as
  source validation evidence.
- `source_failure`: remote command reached the source build/test/lint phase and
  failed with source diagnostics.
- `toolchain_blocker`: selected worker cannot run the requested lane, such as
  missing `cargo-clippy`.
- `transport_timeout`: `rch` timed out or lost transport before a source verdict.
- `local_fallback_refused`: `rch` correctly refused local fallback, so no source
  verdict exists.
- `missing_remote_proof`: log lacks selected worker, remote command, or final
  verdict evidence.

## Required Evidence Fields

Each case records:

- `case_id`
- `validation_command`
- `selected_worker`
- `remote_command_started`
- `remote_command_finished`
- `remote_exit_code`
- `observed_log_markers`
- `verdict`
- `reason_code`
- `source_evidence`
- `remediation`

`source_evidence` is only true for `source_pass` and `source_failure`.
Infrastructure and proof-boundary verdicts must remain false so agents do not
accidentally treat a missing toolchain component or SSH timeout as a code result.

## Closeout Guidance

Agent Mail and bead closeout should include:

1. command
2. worker id
3. verdict
4. reason code
5. whether source evidence exists
6. next remediation command or action

This classifier complements the preflight contract in
[`RCH_VALIDATION_PREFLIGHT_CONTRACT_V1.md`](./RCH_VALIDATION_PREFLIGHT_CONTRACT_V1.md).
Preflight predicts whether a worker should be able to run the lane; this
classifier explains what happened after an attempted run.
