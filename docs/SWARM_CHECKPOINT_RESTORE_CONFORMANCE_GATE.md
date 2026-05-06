# SWARM_CHECKPOINT_RESTORE_CONFORMANCE_GATE

`scripts/swarm_checkpoint_restore_conformance_gate.sh` validates that the
checkpoint bundle and restore planner stay truthful when stitched together.

The gate is report-only. It does not reopen beads, transfer ownership, release
reservations, or execute Cargo. It only checks whether the checkpoint and
restore artifacts are internally consistent and still honor the SWARM-CTRL-XI
restore safety rules.

## Required Inputs

- `--checkpoint-bundle-json`
- `--checkpoint-restore-plan-json`

## Artifacts

- `swarm_checkpoint_restore_conformance_report.json`
- `events.jsonl`
- `commands.txt`
- `report.md`

## Core Invariants

1. Stale or incomplete checkpoints must not be promoted into restorable plans.
2. Local-fallback heavy-proof truth must stay fail closed.
3. Contradictory ownership or contact-first drift must not downgrade below
   `fail_closed`.
4. Salvage manual-review pressure must not be ignored by a `resume` plan.
5. `resume` requires a clean comparison set with no unresolved drift or missing
   current comparisons.
6. Bundle and plan artifact paths must resolve to real evidence.

## Validation

```bash
bash -n scripts/swarm_checkpoint_restore_conformance_gate.sh
bash -n scripts/e2e/swarm_checkpoint_restore_conformance_gate_smoke.sh
shellcheck -x scripts/swarm_checkpoint_restore_conformance_gate.sh scripts/e2e/swarm_checkpoint_restore_conformance_gate_smoke.sh
jq empty docs/swarm_checkpoint_restore_conformance_gate_contract_v1.json
bash scripts/e2e/swarm_checkpoint_restore_conformance_gate_smoke.sh check
bash scripts/e2e/swarm_checkpoint_restore_conformance_gate_smoke.sh selftest
git diff --check -- docs/SWARM_CHECKPOINT_RESTORE_CONFORMANCE_GATE.md docs/swarm_checkpoint_restore_conformance_gate_contract_v1.json scripts/swarm_checkpoint_restore_conformance_gate.sh scripts/e2e/swarm_checkpoint_restore_conformance_gate_smoke.sh
```
