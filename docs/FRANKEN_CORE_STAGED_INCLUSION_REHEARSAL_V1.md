# Franken-Core Staged Inclusion Rehearsal V1

Status: active
Primary bead: `bd-4w7h9.6`
Parent wave: `bd-4w7h9`
Machine-readable contract: `docs/franken_core_staged_inclusion_rehearsal_v1.json`

## Scope

This rehearsal models what would change if `crates/franken-core` were considered
for workspace membership. It does not edit root `Cargo.toml`; it emits an
artifact describing the simulated transition, risks, validation gates, and
rollback requirements.

The rehearsal is consumable by the final acceptance suite and is intentionally
bounded to deterministic metadata inspection:

- root workspace `members` and `exclude` state
- `crates/franken-core` package name and feature keys
- existing workspace member package names
- simulated membership add/remove operations
- RCH-wrapped validation blast radius
- rollback steps

## Supported Modes

| Mode | Use |
| --- | --- |
| `current` | Default live mode; root `Cargo.toml` must still exclude `crates/franken-core`. |
| `included_artifact` | Fixture/artifact mode for a generated manifest that already models inclusion. |

Ambiguous topology, such as a manifest that both includes and excludes
`crates/franken-core`, fails closed.

## Output Contract

`scripts/franken_core_staged_inclusion_rehearsal.sh` writes:

- `staged_inclusion_rehearsal.json`
- `simulated_workspace_patch.json`
- `events.jsonl`
- `commands.txt`
- `report.md`

The report always sets `mutates_root_cargo_toml` to `false`.

## Validation

```bash
jq empty docs/franken_core_staged_inclusion_rehearsal_v1.json
bash -n scripts/franken_core_staged_inclusion_rehearsal.sh
bash -n scripts/e2e/franken_core_staged_inclusion_rehearsal_smoke.sh
bash scripts/e2e/franken_core_staged_inclusion_rehearsal_smoke.sh check
bash scripts/e2e/franken_core_staged_inclusion_rehearsal_smoke.sh negative
git diff --check -- docs/FRANKEN_CORE_STAGED_INCLUSION_REHEARSAL_V1.md docs/franken_core_staged_inclusion_rehearsal_v1.json scripts/franken_core_staged_inclusion_rehearsal.sh scripts/e2e/franken_core_staged_inclusion_rehearsal_smoke.sh
```
