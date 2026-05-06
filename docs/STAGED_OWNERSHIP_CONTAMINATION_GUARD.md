# Staged Ownership Contamination Guard

`scripts/staged_ownership_contamination_guard.sh` prevents accidental
piggyback commits in multi-agent sessions. It compares staged paths against the
current bead write set and an Agent Mail reservation snapshot, then fails closed
when the index contains files owned by another bead or agent.

The guard never mutates the index.

## Operator Flow

Before committing, inspect the staged index and run the guard:

```bash
git diff --cached --name-status
./scripts/staged_ownership_contamination_guard.sh \
  --agent-id ScarletOwl \
  --bead-id bd-2wp35 \
  --allowed-path scripts/staged_ownership_contamination_guard.sh \
  --allowed-path scripts/e2e/staged_ownership_contamination_guard_smoke.sh \
  --allowed-path docs/STAGED_OWNERSHIP_CONTAMINATION_GUARD.md \
  --allowed-path .beads/issues.jsonl \
  --reservation-snapshot-json /tmp/agent-mail-reservations.json
```

For `.beads/issues.jsonl`, the guard requires scoped issue-line evidence. A
shared `.beads` staging operation passes only when the touched bead ids are
limited to the current bead. This keeps routine bead exports possible without
allowing unrelated bead movement to hide inside the shared JSONL file.

## Artifacts

The guard writes:

- `staged_ownership_report.json`
- `events.jsonl`
- `commands.txt`
- `report.md`

The report includes offending paths, expected owners, reservation holders, and
remediation guidance. Missing reservation snapshots are visible degraded mode;
they are not treated as silent proof of ownership.

## Validation

```bash
bash -n scripts/staged_ownership_contamination_guard.sh
bash -n scripts/e2e/staged_ownership_contamination_guard_smoke.sh
./scripts/e2e/staged_ownership_contamination_guard_smoke.sh check
./scripts/e2e/staged_ownership_contamination_guard_smoke.sh selftest
```
