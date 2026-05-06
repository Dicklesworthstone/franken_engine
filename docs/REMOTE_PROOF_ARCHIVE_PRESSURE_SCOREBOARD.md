# Remote Proof Archive Pressure Scoreboard

`scripts/remote_proof_archive_pressure_scoreboard.sh` is the SWARM-CTRL-VI
archive-pressure advisory surface. It composes four already-deterministic
evidence bundles into one bounded operator recommendation:

- the retention class ledger
- the compaction plan
- the archive pack snapshot
- the GC guard report

## Purpose

Archive-pressure response should not be improvised from one artifact at a time.
This scoreboard answers a narrower question: can storage pressure be relieved
honestly right now, and if so, is the first safe move to retain, compact, cool,
or evict?

The classifier is fail-closed. If the upstream bundle IDs drift, if the guard
already failed closed, or if active or salvage-pinned evidence still prevents
honest pressure relief, the scoreboard emits preservation guidance instead of
speculative eviction advice.

## Usage

```bash
./scripts/remote_proof_archive_pressure_scoreboard.sh \
  --retention-ledger-json artifacts/retention_ledger.json \
  --compaction-plan-json artifacts/remote_proof_compaction_plan.json \
  --gc-guard-report-json artifacts/remote_proof_gc_guard_report.json \
  --archive-pack-json artifacts/archive_pack.json \
  --output-dir /tmp/remote-proof-archive-pressure
```

Required inputs:

- `--retention-ledger-json`
- `--compaction-plan-json`
- `--gc-guard-report-json`
- `--archive-pack-json`

Optional:

- `--output-dir`

## Output

Each run emits:

- `remote_proof_archive_pressure_scoreboard.json`
- `events.jsonl`
- `commands.txt`
- `report.md`

The scoreboard schema is:

- `franken-engine.remote-proof-archive-pressure-scoreboard.v1`

Key fields:

- `bundle_id`
- `pressure_level`
- `advisory`
- `recommended_action`
- `reason`
- `class_counts`
- `compaction_summary`
- `archive_summary`
- `gc_guard_summary`
- `policy_findings[]`
- `hash_basis`
- `upstream_artifact_paths`
- `artifact_paths`

## Advisory Classes

- `retain`
  - `recommended_action`: `retain_current_residency`
  - exit code `0`
- `compaction_first`
  - `recommended_action`: `compact_before_eviction`
  - exit code `75`
- `cool_archive`
  - `recommended_action`: `cool_without_gc`
  - exit code `75`
- `evict_cold_archive`
  - `recommended_action`: `evict_archived_bundle`
  - exit code `42`
- `fail_closed`
  - `recommended_action`: one of:
    - `preserve_active_evidence`
    - `preserve_pinned_evidence`
    - `manual_review_required`
  - exit code `42`

## Decision Rules

The current policy is intentionally bounded:

- low pressure plus `deny_gc` / `keep_hot` becomes `retain`
- elevated or critical pressure with compactable duplicate groups becomes
  `compaction_first`
- critical pressure plus a verified cold archive and `allow_gc` /
  `delete_cold_archived_bundle` becomes `evict_cold_archive`
- active replay-critical protection or salvage pinning under pressure becomes
  `fail_closed`
- upstream GC guard `cool_only` becomes `cool_archive`

## Proof Requirements

`scripts/e2e/remote_proof_archive_pressure_scoreboard_smoke.sh` must prove:

- low-pressure retain advisory fixture
- compaction-first remediation fixture
- cold-archive eviction fixture under critical pressure
- active-or-salvage-pinned fail-closed advisory fixture
- repeated identical inputs preserve the same scoreboard hash
