# IDEA-WIZARD-IV Validation Impact Planner

`bd-k53rr` adds the IDEA-WIZARD-IV adapter for focused validation planning.
It reuses `scripts/swarm_validation_planner.sh` and emits the contract-required
`validation_impact_plan.json` shape for the saturation convergence wave.

The planner is advisory only. It never executes recommended validation
commands, never claims or closes beads, never repairs Agent Mail, and never
mutates git or RCH workers.

## Inputs

```bash
./scripts/idea_wizard_iv_validation_impact_planner.sh \
  --bead-id bd-k53rr \
  --changed-path crates/franken-engine/src/lib.rs \
  --output-dir /tmp/franken-engine-iw4-validation-impact
```

Supported pass-through inputs mirror the underlying swarm validation planner:

- `--changed-path PATH`
- `--planned-write-path PATH`
- `--proof-cost-history-json PATH`
- `--reservation-snapshot-json PATH`
- `--in-progress-json PATH`
- `--native-route-advisory-json PATH`
- `--package PACKAGE`
- `--test-target TARGET`
- `--allow-broad`

## Outputs

The adapter writes:

- `validation_impact_plan.json`
- `run_manifest.json`
- `events.jsonl`
- `commands.txt`
- `report.md`
- `swarm_validation_planner/plan.json`
- `swarm_validation_planner/collision_receipt.json`

The `validation_impact_plan.json` report includes the changed paths,
recommended commands, cost class, proof sufficiency, RCH wrapping status,
omitted commands, warnings, and links to the underlying planner artifacts.

## Decision Semantics

| Underlying planner decision | IDEA-WIZARD-IV decision | Proof sufficiency |
| --- | --- | --- |
| `admit` | `green` | `sufficient_focused` |
| `admit_narrow` | `degraded` | `sufficient_with_degraded_coordination` |
| `fail_closed` | `fail_closed` | `insufficient` |

Any heavy Cargo recommendation that is not `rch exec -- env
CARGO_TARGET_DIR=` wrapped is converted to a fail-closed validation-impact
finding.

## Validation

```bash
bash -n scripts/idea_wizard_iv_validation_impact_planner.sh
bash -n scripts/e2e/idea_wizard_iv_validation_impact_planner_smoke.sh
bash scripts/e2e/idea_wizard_iv_validation_impact_planner_smoke.sh check
git diff --check -- docs/IDEA_WIZARD_IV_VALIDATION_IMPACT_PLANNER.md scripts/idea_wizard_iv_validation_impact_planner.sh scripts/e2e/idea_wizard_iv_validation_impact_planner_smoke.sh docs/idea_wizard_iv_saturation_convergence_v1.json
```
