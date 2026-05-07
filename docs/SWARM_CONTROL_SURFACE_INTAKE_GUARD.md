# SWARM_CONTROL_SURFACE_INTAKE_GUARD

`bd-1vx5g` adds a planning-time intake guard for future swarm-control ideas. The
guard checks a proposed bead or feature against the normalized control-surface
catalog before agents create another SWARM-CTRL, SWARM-AUTOPILOT, queue, or RCH
control-plane lane.

The guard is advisory only. It emits recommended actions and command text, but it
does not create beads, update dependencies, send Agent Mail, release
reservations, run Cargo, run RCH, or mutate git.

## Inputs

- `--proposal-json`: proposed work item with title, description, tags, and
  acceptance criteria
- `--catalog-json`: normalized control-surface catalog
- `--br-snapshot-json`: optional open/closed bead title snapshot

## Recommended Actions

- `create_new`: the proposal is genuinely new and has enough acceptance detail
- `extend_existing`: the proposal is a successor or extension of a cataloged
  surface
- `make_child_of`: the proposal should be attached below an existing surface
  owner or track
- `duplicate_reject`: the proposal duplicates an existing surface or contains an
  unsafe live-mutation claim
- `needs_manual_review`: the proposal lacks acceptance criteria or is too
  ambiguous to classify

All `br` commands in the report are text suggestions only.

## Validation

```bash
jq empty scripts/testdata/swarm_control_surface_intake_guard/cases.json
bash -n scripts/swarm_control_surface_intake_guard.sh scripts/e2e/swarm_control_surface_intake_guard_smoke.sh
shellcheck -x scripts/swarm_control_surface_intake_guard.sh scripts/e2e/swarm_control_surface_intake_guard_smoke.sh
bash scripts/e2e/swarm_control_surface_intake_guard_smoke.sh check
bash scripts/e2e/swarm_control_surface_intake_guard_smoke.sh selftest
git diff --check -- docs/SWARM_CONTROL_SURFACE_INTAKE_GUARD.md scripts/swarm_control_surface_intake_guard.sh scripts/e2e/swarm_control_surface_intake_guard_smoke.sh scripts/testdata/swarm_control_surface_intake_guard/cases.json
```
