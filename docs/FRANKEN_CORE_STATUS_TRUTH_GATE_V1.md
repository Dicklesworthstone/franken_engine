# Franken-Core Status Truth Gate V1

Status: active
Primary bead: `bd-4w7h9.5`
Parent wave: `bd-4w7h9`
Machine-readable contract: `docs/franken_core_status_truth_gate_v1.json`

## Scope

This gate keeps `crates/franken-core` status claims aligned with the real Cargo
manifests and the graduation contract. The current truthful state is narrow:

- root `Cargo.toml` excludes `crates/franken-core`
- `crates/franken-core/Cargo.toml` exists as a standalone manifest
- standalone compileability evidence superseded the old missing-module blocker
- workspace graduation is not complete and remains blocked on `bd-4w7h9.8`

The gate is read-only. It writes report artifacts, but it does not edit docs,
change manifests, run Cargo, run RCH, create beads, or approve workspace
membership.

## Historical Evidence

| Bead | Role |
| --- | --- |
| `bd-ucemx` | Historical exclusion/reference-only context from the missing-module era. |
| `bd-zsais` | Superseding standalone manifest compileability evidence. |
| `bd-dymfz` | Superseding standalone franken-core test baseline evidence. |
| `bd-nwhcp` | Superseding executable timer-regression evidence. |
| `bd-4w7h9.8` | Required final acceptance suite before any workspace-membership claim. |

## Fail-Closed Rules

The gate fails closed when it finds:

- a root manifest state that contradicts the excluded-standalone contract
- a missing or malformed `crates/franken-core` package manifest
- stale reference-only or missing-module claims without superseding bead context
- over-eager claims that `franken-core` is already included, workspace-ready, or
  complete
- missing canonical wording that says both excluded and standalone compileable

Every failure includes a source path, reason code, snippet, and remediation text.

## Canonical Wording

Use wording with this shape:

```text
crates/franken-core remains excluded from the root workspace, while its
standalone manifest is compileable. The old reference-only/missing-module state
is superseded by bd-zsais, bd-dymfz, and bd-nwhcp. Workspace graduation remains
blocked until bd-4w7h9.8 passes.
```

Do not say the crate is workspace-ready, included in the workspace, or complete
unless the final acceptance suite has passed and a separate topology bead has
changed root `Cargo.toml`.

## Outputs

`scripts/franken_core_status_truth_gate.sh` writes:

- `truth_report.json`
- `events.jsonl`
- `commands.txt`
- `report.md`

## Validation

```bash
jq empty docs/franken_core_status_truth_gate_v1.json
bash -n scripts/franken_core_status_truth_gate.sh
bash -n scripts/e2e/franken_core_status_truth_gate_smoke.sh
bash scripts/e2e/franken_core_status_truth_gate_smoke.sh check
bash scripts/e2e/franken_core_status_truth_gate_smoke.sh negative
git diff --check -- docs/FRANKEN_CORE_STATUS_TRUTH_GATE_V1.md docs/franken_core_status_truth_gate_v1.json scripts/franken_core_status_truth_gate.sh scripts/e2e/franken_core_status_truth_gate_smoke.sh
```
