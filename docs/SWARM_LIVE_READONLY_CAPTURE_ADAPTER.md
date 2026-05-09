# SWARM Live Read-Only Capture Adapter

`scripts/swarm_live_readonly_capture_adapter.sh` is an optional bridge from
live read-only coordination commands to the fixture-fed bundle writer introduced
for `bd-ep8y0.2`.

The adapter does not replace `docs/swarm_ops_state_contract_v1.json`, and it
does not replace the `bd-x82vp` resource lease planner. It prepares evidence for
those surfaces.

## Inputs

The adapter can copy fixture JSON files or run these read-only commands:

```bash
br ready --json
br list --status=in_progress --json
br sync --status --json
bv --recipe actionable --robot-plan
rch status --workers --jobs --json
rch queue --json
git status --short
git diff --check -- <paths>
```

Agent Mail evidence is accepted only from an operator-supplied JSON file. The
adapter does not query live Agent Mail, send Agent Mail, release reservations, or
modify contacts.

## Example

```bash
./scripts/swarm_live_readonly_capture_adapter.sh \
  --output-dir /tmp/swarm-live-readonly-capture \
  --agent-mail-json /tmp/agent-mail-snapshot.json \
  --resource-pressure-json /tmp/resource-pressure.json \
  --proof-transcript-json /tmp/proof-transcript.json \
  --diff-path scripts/swarm_live_readonly_capture_adapter.sh \
  --diff-path scripts/swarm_live_readonly_snapshot_bundle.sh
```

The adapter writes:

- `capture_adapter.json`
- `commands.txt`
- `events.jsonl`
- `report.md`
- `bundle/snapshot.json`
- `bundle/swarm_ops_state_bundle.json`
- `bundle/redaction_report.json`

## Degraded Mode

Missing Agent Mail, resource-pressure, proof-transcript, or queue evidence stays
visible as degraded evidence in `bundle/snapshot.json`. Failed read-only capture
commands become `capture_error` inputs and are downgraded by the bundle writer.
Local RCH fallback markers fail closed.

## Mutation Boundary

The adapter refuses mutating command plans before capture. Forbidden command
families include bead updates or closes, Git staging or reset commands, heavy
Cargo commands, `rch exec`, remote worker disable commands, and destructive
filesystem cleanup.

It never:

- updates, closes, reopens, assigns, or sync-flushes beads
- sends or queries live Agent Mail
- runs Cargo
- runs `rch exec`
- disables or mutates workers
- cleans target directories
- creates a scheduler or resource planner

## Validation

```bash
bash -n scripts/swarm_live_readonly_capture_adapter.sh
bash -n scripts/e2e/swarm_live_readonly_capture_adapter_smoke.sh
jq empty scripts/testdata/swarm_live_readonly_capture_adapter/cases.json
./scripts/e2e/swarm_live_readonly_capture_adapter_smoke.sh check
./scripts/e2e/swarm_live_readonly_capture_adapter_smoke.sh selftest
git diff --check -- docs/SWARM_LIVE_READONLY_CAPTURE_ADAPTER.md scripts/swarm_live_readonly_capture_adapter.sh scripts/e2e/swarm_live_readonly_capture_adapter_smoke.sh scripts/testdata/swarm_live_readonly_capture_adapter/cases.json
```
