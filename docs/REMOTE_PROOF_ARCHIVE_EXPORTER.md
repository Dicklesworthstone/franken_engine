# Remote Proof Archive Exporter

`scripts/remote_proof_archive_exporter.sh` is the fixture-driven archive handoff
surface for SWARM-CTRL-VI. It can either:

- generate an archive pack from a normalized source-file inventory, or
- verify a preserved archive pack against the residency and compaction evidence

## Inputs

Required:

- `--residency-manifest-json`
- `--compaction-plan-json`

Optional:

- `--archive-source-files-json`
- `--archive-pack-json`
- `--output-dir`

At least one of `--archive-source-files-json` or `--archive-pack-json` must be
provided.

## Outputs

Each run emits:

- `archive_pack.json`
- `restore_verification_report.json`
- `events.jsonl`
- `commands.txt`
- `report.md`

The archive pack is the replay-ready export surface:

- schema `franken-engine.remote-proof-archive-pack.v1`
- deterministic archived artifact list
- compacted duplicate replay groups already collapsed to retained paths
- manifest hash under `hash_basis.archive_manifest_hash`

The restore verification report is the acceptance surface:

- schema `franken-engine.remote-proof-archive-restore-verification.v1`
- explicit missing replay paths
- explicit unexpected or missing retained paths
- explicit tampered manifest-hash detection

## Safety Rules

- Replay-critical artifacts from the residency manifest must remain present after
  compaction.
- Compactable duplicate replay artifacts are archived only at their retained
  path from the compaction plan.
- A preserved archive pack fails closed if its manifest hash no longer matches
  its actual contents.
- The exporter never fetches from workers or reads live archive state.

## Proof Expectations

`scripts/e2e/remote_proof_archive_exporter_smoke.sh` must prove:

- archive export success with replay-critical and status artifacts
- missing replay-critical artifact fail-closed
- restore verification success with stable hashes
- tampered archive restore fail-closed
