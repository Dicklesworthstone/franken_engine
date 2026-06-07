# Franken-Core Status Truth Gate V1

Status: active
Primary bead: `bd-4w7h9.5`
Parent wave: `bd-4w7h9`
Machine-readable contract: `docs/franken_core_status_truth_gate_v1.json`

## Scope

This gate keeps `crates/franken-core` status claims in the root README, the
franken-core README, status docs, and machine contracts aligned with the real
Cargo manifests and the graduation contract. The current truthful state is:

- root `Cargo.toml` includes `crates/franken-core` as a workspace member
- root `Cargo.toml` must not exclude `crates/franken-core`
- `crates/franken-core/Cargo.toml` exists as a standalone manifest
- standalone compileability evidence superseded the old missing-module blocker
- workspace inclusion is complete under `bd-cixqu.10.7`
- `bd-cixqu.10.8` guards against silently re-excluding the crate

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
| `bd-4w7h9.8` | Final acceptance suite that approved an explicit workspace-membership bead. |
| `bd-cixqu.10.7` | Explicit topology bead that includes `crates/franken-core` in the root workspace. |
| `bd-cixqu.10.8` | Negative guard preventing future `workspace.exclude` entries for `crates/franken-core`. |

## Fail-Closed Rules

The gate fails closed when it finds:

- a root manifest state that contradicts the included-workspace contract
- any forbidden root `workspace.exclude` entry for `crates/franken-core`
- a missing or malformed `crates/franken-core` package manifest
- stale reference-only or missing-module claims without superseding bead context
- stale claims that `franken-core` remains excluded
- missing canonical wording that says both included and standalone compileable

Every failure includes a source path, reason code, snippet, and remediation text.

## Canonical Wording

Use wording with this shape:

```text
crates/franken-core is included in the root workspace as a first-class member,
while its standalone manifest remains compileable. The old
reference-only/missing-module state is superseded by bd-zsais, bd-dymfz, and
bd-nwhcp. bd-cixqu.10.8 forbids reintroducing a workspace.exclude entry for
crates/franken-core.
```

Do not say the crate remains excluded except in explicitly historical or
negative-test context.

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
git diff --check -- README.md docs/FRANKEN_CORE_STATUS_TRUTH_GATE_V1.md docs/franken_core_status_truth_gate_v1.json scripts/franken_core_status_truth_gate.sh scripts/e2e/franken_core_status_truth_gate_smoke.sh
```
