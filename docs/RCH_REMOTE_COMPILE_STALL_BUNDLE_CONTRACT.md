# RCH_REMOTE_COMPILE_STALL_BUNDLE_CONTRACT

`docs/rch_remote_compile_stall_bundle_contract_v1.json` defines the
contract-only evidence bundle for a real `frankenengine-engine` remote compile
stall.

The current producer chain is:

- `scripts/rch_remote_compile_stall_bundle_capture.sh`
- `scripts/e2e/rch_remote_compile_stall_repro_harness.sh`
- `scripts/e2e/rch_remote_compile_stall_truth_gate.sh`

It is evidence only. The bundle must not be described as a live fix, tracker
mutation surface, reservation mutation surface, Agent Mail mutation surface, or
remote worker mutation surface.

## Required Snapshots

The bundle must preserve four required remote-only snapshots:

- `bead_metadata` with the tracked `bead_id`
- `remote_command_receipt` with the exact heavy command under test
- `rch_queue_snapshot` equivalent to `rch queue --json`
- `rch_status_workers_jobs_snapshot` equivalent to
  `rch status --workers --jobs --json`

Together these required snapshots must preserve the minimal stall subject:

- `bead_id`
- `command`
- `worker_id`
- `build_id`
- `heartbeat.phase`
- `heartbeat.detail`
- `last_progress_epoch_seconds`
- `progress_age_seconds`
- `local_fallback_observed`

Missing required remote snapshots fail closed. This contract is intentionally
repo-local and deterministic so later scripts and smoke tests can target it
directly without a live worker.

## Optional Snapshots

Optional supporting snapshots may remain absent without erasing a stall claim:

- `worker_inventory_snapshot`
- `command_log_excerpt`
- `operator_note`

Missing optional snapshots degrade trust. They do not silently upgrade the
bundle into a confirmed remote stall.

## Truth States

- `confirmed`: all required and optional snapshots are present, queue and worker
  snapshots agree on the same build and worker, and the local-fallback fail-closed
  marker was not observed
- `degraded`: the required stall tuple is present, no contradictions are
  observed, the local-fallback fail-closed marker was not observed, but one or
  more optional snapshots are missing
- `blocked`: required snapshots are missing or contradictory queue or worker
  snapshots prevent a truthful remote stall claim
- `contaminated`: local fallback was observed and must fail closed, so the bundle
  is not valid remote stall truth even if the other snapshots appear internally
  consistent

`contaminated` is stricter than `blocked`: the evidence is present, but it is no
longer safe to present as remote-only proof.

## Expected Bundle Fields

The bundle must preserve these top-level fields:

- `stall_bundle_id`
- `bead_id`
- `capture_decision`
- `truth_state`
- `captured_at_epoch_seconds`
- `local_fallback_observed`
- `stall_subject`
- `snapshot_health`
- `queue_snapshot`
- `status_snapshot`
- `blockers`
- `artifact_paths.stall_bundle_json`
- `artifact_paths.events_jsonl`
- `artifact_paths.commands_txt`
- `artifact_paths.summary_md`

Expected enumerations:

- `capture_decision`: `captured`, `captured_degraded`, or `fail_closed`
- `truth_state`: `confirmed`, `degraded`, `blocked`, or `contaminated`

## Fail-Closed Rules

- Missing required remote snapshots fail closed.
- contradictory queue or worker snapshots fail closed.
- local fallback observed fails closed by forcing `truth_state=contaminated` and
  `capture_decision=fail_closed`.
- `progress_age_seconds` must not contradict `last_progress_epoch_seconds` and
  the snapshot timestamps.
- The bundle must not claim that a remote stall is fixed, retried, or resolved automatically.
- The bundle must not claim it mutates beads, reservations, Agent Mail, or workers.

## Expected Outputs

The capture script emits at least:

- `stall_bundle.json`
- `events.jsonl`
- `commands.txt`
- `summary.md`

The repro harness composes the bundle into `repro_report.json`, and the truth
gate composes the contract, bundle, and repro report across healthy remote
completion, explicit timeout, fresh-heartbeat/frozen-progress stall, and
local-fallback fail-closed contamination fixtures.

## Validation

```bash
jq empty docs/rch_remote_compile_stall_bundle_contract_v1.json
bash -n scripts/e2e/rch_remote_compile_stall_bundle_contract_smoke.sh
shellcheck -x scripts/e2e/rch_remote_compile_stall_bundle_contract_smoke.sh
bash scripts/e2e/rch_remote_compile_stall_bundle_contract_smoke.sh check
bash scripts/e2e/rch_remote_compile_stall_bundle_contract_smoke.sh selftest
bash -n scripts/rch_remote_compile_stall_bundle_capture.sh scripts/e2e/rch_remote_compile_stall_repro_harness.sh scripts/e2e/rch_remote_compile_stall_truth_gate.sh scripts/e2e/rch_remote_compile_stall_truth_gate_smoke.sh
shellcheck -x scripts/rch_remote_compile_stall_bundle_capture.sh scripts/e2e/rch_remote_compile_stall_repro_harness.sh scripts/e2e/rch_remote_compile_stall_truth_gate.sh scripts/e2e/rch_remote_compile_stall_truth_gate_smoke.sh
bash scripts/e2e/rch_remote_compile_stall_truth_gate_smoke.sh check
bash scripts/e2e/rch_remote_compile_stall_truth_gate_smoke.sh selftest
git diff --check -- docs/RCH_REMOTE_COMPILE_STALL_BUNDLE_CONTRACT.md docs/rch_remote_compile_stall_bundle_contract_v1.json scripts/rch_remote_compile_stall_bundle_capture.sh scripts/e2e/rch_remote_compile_stall_repro_harness.sh scripts/e2e/rch_remote_compile_stall_truth_gate.sh scripts/e2e/rch_remote_compile_stall_truth_gate_smoke.sh scripts/testdata/rch_remote_compile_stall_truth_gate
```
