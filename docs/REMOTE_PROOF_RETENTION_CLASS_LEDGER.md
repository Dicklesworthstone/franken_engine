# Remote Proof Retention Class Ledger

`scripts/remote_proof_retention_class_ledger.sh` is the deterministic retention
classifier for the SWARM-CTRL-VI archive layer. It consumes already-emitted
remote-proof evidence and publishes one normalized residency manifest that later
archive, restore, and GC surfaces can trust without inferring retention policy
ad hoc.

## Inputs

Required inputs:

- `--bundle-report-json`
- `--mirror-manifest-json`
- `--batch-manifest-json`
- `--salvage-receipt-json`

Optional input:

- `--output-dir`

The classifier is shell-only. It does not call `cargo`, `rch`, or any live
worker APIs.

## Emitted Artifacts

The run directory always contains:

- `retention_class_ledger.json`
- `evidence_residency_manifest.json`
- `events.jsonl`
- `commands.txt`
- `report.md`

`retention_class_ledger.json` is the operator summary. It records the
classification decision, validation errors, class counts, and the hash linkage
to the manifest.

`evidence_residency_manifest.json` is the downstream authority. It contains the
normalized per-artifact entries, the active batch/salvage context, and the
stable hash basis for repeated replay.

## Retention Classes

- `hot_replay_critical`: replay-critical artifacts that must stay hot because
  upstream bundle or mirror evidence marks them as necessary for replay.
- `warm_operator_inspectable`: control-plane outputs and selected artifacts that
  should remain warm for bounded operator inspection or immediate reuse.
- `salvage_pinned`: evidence pinned by an active salvage workflow such as orphan
  reconciliation or live-compile salvage.
- `cold_archival`: inspect-only artifacts that are not replay-critical and are
  not pinned by salvage state.

Classification precedence is strict:

1. salvage pinning
2. replay-critical hot residency
3. warm operator-inspectable retention
4. cold archival

## Fail-Closed Rules

The ledger exits `42` instead of emitting a passing classification when any of
the following are true:

- bundle, mirror, and salvage bundle identities drift
- the batch manifest does not actually contain the target bundle
- the bundle lacks expected worker or target-dir identity
- the mirror lacks usable artifact evidence
- one logical artifact path carries conflicting content addresses

## Proof Expectations

`scripts/e2e/remote_proof_retention_class_ledger_smoke.sh` must prove:

- replay-critical bundle artifacts stay hot
- salvage-receipt evidence is pinned after bundle failure
- inspect-only artifacts demote to cold archival
- repeated identical inputs preserve the same manifest hash
