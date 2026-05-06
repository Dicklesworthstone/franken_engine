# Stale Lock And Stalled Bead Recommender

`scripts/stale_lock_stalled_bead_recommender.sh` produces evidence packets for
in-progress beads that may be abandoned. It does not reopen beads, clear
assignees, release reservations, or mutate the worktree.

The recommender is intentionally conservative. A bead is `safe_to_reopen` only
when the owner is stale, Agent Mail snapshots are available, there are no active
reservations, there is no recent thread activity, there is no recent git
activity, and the bead is not P0/P1.

## Inputs

- `--in-progress-json`: required output from `br list --status=in_progress --json`
- `--agent-profiles-json`: Agent Mail profile snapshot with owner
  `last_active_ts` or `last_active_epoch_seconds`
- `--thread-timestamps-json`: inbox/thread timestamps for owner contact and
  bead-specific messages
- `--file-reservations-json`: active file reservations
- `--git-activity-json`: optional recent touched-path or commit activity

Missing Agent Mail inputs put the report in degraded mode. Degraded
recommendations require manual confirmation and never produce
`safe_to_reopen=true`.

## Output Fields

- `stale_lock_recommendations`: one entry per in-progress bead
- `safe_to_reopen`: bead ids where reopening is evidence-supported
- `contact_first`: bead ids that require owner contact or manual confirmation
- `evidence`: owner activity, reservation counts, thread counts, git activity,
  priority guard state, and degraded reasons
- `suggested_br_commands`: exact `br update` commands emitted only for safe
  reopen cases

Safe reopen commands use:

```bash
br update <bead-id> --status open --assignee ""
```

## Operator Sequence

1. Check your inbox and recent thread messages for the bead owner.
2. Contact the owner by Agent Mail when `contact_first=true`.
3. Inspect the recommendation evidence and active reservations.
4. Run the suggested `br update` command only when the report says
   `safe_to_reopen=true`.
5. Send a closeout or takeover message with the evidence path before starting
   new work on the reopened bead.

For high-priority P0/P1 beads or recently touched files, contact first even when
the owner appears stale. Slow proof work can look abandoned while an `rch`
compile is still alive.

## Smoke Validation

```bash
bash -n scripts/stale_lock_stalled_bead_recommender.sh
bash -n scripts/e2e/stale_lock_stalled_bead_recommender_smoke.sh
./scripts/e2e/stale_lock_stalled_bead_recommender_smoke.sh check
./scripts/e2e/stale_lock_stalled_bead_recommender_smoke.sh selftest
```

The smoke suite covers active owners, stale owners with no reservations, stale
owners with recent git activity, missing Agent Mail degraded mode, and
high-priority beads that require contact first.
