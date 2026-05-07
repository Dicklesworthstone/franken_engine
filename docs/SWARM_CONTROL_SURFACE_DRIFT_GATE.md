# SWARM_CONTROL_SURFACE_DRIFT_GATE

`bd-cinsv` adds the SWARM-CTRL-XVII drift gate for the control-surface catalog.
The gate answers whether the catalog still truthfully covers the repo-local
swarm-control surfaces that a router or future intake guard would use.

The gate is artifact-fed and advisory only. It consumes the normalized catalog
from `scripts/swarm_control_surface_catalog_normalizer.sh`, optional checked-in
script inventory, and optional bead status snapshots. It does not query live
`br`, Agent Mail, git, RCH, Cargo, or workers, and it does not mutate any source
of truth.

## Inputs

- `--catalog-json`: normalized `swarm_control_surface_catalog.json`
- `--script-inventory-json`: optional array or object containing repo-relative
  script paths that should be represented in the catalog
- `--bead-status-json`: optional issue snapshot with `id` and `status` fields
- `--workspace-root`: repo or fixture root used for smoke-script shape checks

## Fail-Closed Drift

The gate exits 42 when it finds any of these conditions:

- a script inventory path is absent from every catalog row
- two surfaces share an intent tag without an upstream/downstream relationship
- a catalog row claims live mutation or automatic remediation
- a row has a smoke script that does not expose both `check` and `selftest`
- a validation command contains bare heavy Cargo instead of
  `rch exec -- env CARGO_TARGET_DIR=`
- an owner bead is present in the bead snapshot but is not closed
- the upstream catalog itself is already `fail_closed`

## Outputs

- `control_surface_drift_report.json`
- `events.jsonl`
- `commands.txt`
- `report.md`

The report includes stable finding codes, remediation command text, and artifact
paths. Remediation commands are text only; the gate never runs them.

## Validation

```bash
jq empty scripts/testdata/swarm_control_surface_drift_gate/cases.json
bash -n scripts/swarm_control_surface_drift_gate.sh scripts/e2e/swarm_control_surface_drift_gate_smoke.sh
shellcheck -x scripts/swarm_control_surface_drift_gate.sh scripts/e2e/swarm_control_surface_drift_gate_smoke.sh
bash scripts/e2e/swarm_control_surface_drift_gate_smoke.sh check
bash scripts/e2e/swarm_control_surface_drift_gate_smoke.sh selftest
git diff --check -- docs/SWARM_CONTROL_SURFACE_DRIFT_GATE.md scripts/swarm_control_surface_drift_gate.sh scripts/e2e/swarm_control_surface_drift_gate_smoke.sh scripts/testdata/swarm_control_surface_drift_gate/cases.json
```
