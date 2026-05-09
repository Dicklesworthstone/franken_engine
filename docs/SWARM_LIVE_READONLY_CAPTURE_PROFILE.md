# SWARM Live Read-Only Capture Profile

The SWARM live read-only capture profile defines how operators and agents turn
live coordination observations into fixture input for existing SWARM gates.

Machine-readable profile:
`docs/swarm_live_readonly_capture_profile_v1.json`.

Upstream authority:

- `bd-eozx0` remains the canonical live swarm state contract. This profile
  extends `docs/swarm_ops_state_contract_v1.json`; it does not fork or replace
  the `franken-engine.swarm-ops-state-bundle.v1` schema.
- `bd-x82vp` remains the canonical resource lease planner. This profile may
  provide capture evidence for `docs/SWARM_RESOURCE_LEASE_PLANNER.md`; it does
  not define a second lease planner.

The profile records evidence. It is not a scheduler, autonomous operator,
resource allocator, Agent Mail writer, bead owner, or remote worker controller.

## Scope

The profile covers a capture manifest, redaction policy, freshness windows,
source command transcript hashes, and non-mutation attestation for live evidence
that downstream fixture-fed gates can consume. A complete capture bundle must
include:

- `capture_profile.json`
- `swarm_ops_state_bundle.json`
- `events.jsonl`
- `commands.txt`
- `redaction_report.json`
- `report.md`

The capture bundle feeds the existing SWARM state and lease-planning contracts.
It does not change their output schemas or decisions.

## Source Inventory

Required read-only sources:

- `br ready --json` for ready queue evidence.
- `br list --status=in_progress --json` for active ownership evidence.
- `br sync --status --json` for DB/JSONL freshness evidence.
- `bv --recipe actionable --robot-plan` for ranked advisory work tracks.
- `rch status --workers --jobs --json` for worker and job state.
- `git status --short` for dirty path evidence.
- `git diff --check -- <paths>` for scoped whitespace/conflict evidence.

Optional file-fed sources:

- Agent Mail snapshot JSON exported by an operator or another safe capture
  surface. Validation gates must treat it as an input file and must not query
  live Agent Mail.
- RCH queue JSON from `rch queue --json`.
- Resource pressure JSON from an operator-supplied read-only host snapshot.
- Prior proof transcript files for failed or successful validation attempts.

Each source row in `commands.txt` must record the component, command text or
input-file origin, capture timestamp, mutation class, source command hash, raw
payload hash, and redacted payload hash.

## Freshness And Trust

Freshness windows are intentionally short for live queue and worker state:

- `br`, `bv`, and `git` observations: 300 seconds.
- RCH worker, queue, and resource-pressure observations: 120 seconds.
- Agent Mail snapshots: 300 seconds.
- Prior proof transcripts: 86400 seconds.

Required stale or missing sources block or fail closed. Optional missing sources
become visible `degraded` evidence. A local RCH fallback marker, stale required
`br` truth, command hash mismatch, unredacted secret material, or observed
mutating command must fail closed.

## Redaction

The redaction report must include one row per source and must preserve hashes of
the raw and redacted payloads. It must redact:

- Agent Mail sender tokens, registration tokens, auth headers, contact secrets,
  and reservation secret material.
- Environment values whose names contain `TOKEN`, `SECRET`, `KEY`, `PASSWORD`,
  `COOKIE`, or `AUTH`.
- Home-directory prefixes when a project-relative path is not available.
- Large stdout or stderr payloads beyond 65536 bytes, replacing them with a
  bounded excerpt and sha256 hash.

Unredacted secret material fails closed. Unnormalized home paths or oversized
unredacted payloads block the capture until a safer report is produced.

## Mutation Boundary

The profile is fixture-fed, proof-only, advisory-only, and non-mutating. It
never:

- updates, closes, reopens, assigns, or sync-flushes beads
- releases file reservations
- sends Agent Mail
- queries live Agent Mail during validation
- runs Cargo
- runs `rch exec` or starts remote builds
- mutates remote workers
- changes active queue policy
- repairs target directories
- writes outside the requested output directory
- creates a scheduler or replacement lease planner

Forbidden command evidence includes `br update`, `br close`, `br reopen`,
`git add`, `git commit`, `git reset`, bare heavy Cargo commands, `rch exec`,
remote worker disable commands, and destructive filesystem cleanup commands. A
capture that includes those commands as executed live actions must fail closed.

## Event Keys

Every emitted `events.jsonl` row must include:

- `trace_id`
- `component`
- `event`
- `outcome`
- `error_code`
- `evidence_path`
- `capture_source`
- `source_command_hash`
- `payload_hash`

These keys let downstream gates prove where each advisory decision came from
without relying on chat context.

## Validation

```bash
jq empty docs/swarm_live_readonly_capture_profile_v1.json
git diff --check -- docs/SWARM_LIVE_READONLY_CAPTURE_PROFILE.md docs/swarm_live_readonly_capture_profile_v1.json .beads/issues.jsonl
```
