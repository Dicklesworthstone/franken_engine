# SWARM_NATIVE_DEPENDENCY_HDF5_REPLAY_DRILL

`scripts/swarm_native_dependency_hdf5_replay_drill.sh` is a deterministic
no-mock replay gate for the HDF5 native dependency gap seen during the
`bd-bzbcn` React validation path. It exercises the real checked-in native
dependency routing surfaces end to end:

- requirement inference from the `frankenengine-engine` to `frankenpandas` to
  `hdf5-metno-sys` Cargo/path-dependency closure
- worker native probe normalization for present, missing, and stale HDF5
  evidence
- advisory route planning and retry selection
- ABI cache reuse or quarantine verdicts
- operator status, Agent Mail handoff, and br closeout wording

The drill is fixture-fed and read-only. It does not run Cargo or RCH, install
packages, mutate worker environments, delete target directories, update beads,
or send Agent Mail. Live worker execution is optional operator proof only; the
normal replay gate is deterministic from `scripts/testdata`.

## Artifacts

- `run_manifest.json`
- `events.jsonl`
- `command_trace_ids.json`
- `native_dependency_routing_report.md`
- `step_evidence.json`
- `commands.txt`

## Optional Live Proof

If a future operator needs a live proof, copy the command from the manifest or
fixture exactly and run it through `rch`:

```bash
timeout 1200 rch exec -- env CARGO_TARGET_DIR=/tmp/rch_target_franken_engine_hdf5_drill CARGO_INCREMENTAL=0 cargo test -p frankenengine-engine --test react_compilation_pipeline_integration -- --nocapture
```

That live command is not required for the fixture smoke tests. A missing HDF5
result is a validation environment blocker, not evidence that the source patch failed.

## Validation

```bash
jq empty scripts/testdata/swarm_native_dependency_hdf5_replay_drill/cases.json
bash -n scripts/swarm_native_dependency_hdf5_replay_drill.sh
bash -n scripts/e2e/swarm_native_dependency_hdf5_replay_drill_smoke.sh
bash scripts/e2e/swarm_native_dependency_hdf5_replay_drill_smoke.sh check
bash scripts/e2e/swarm_native_dependency_hdf5_replay_drill_smoke.sh selftest
git diff --check -- docs/SWARM_NATIVE_DEPENDENCY_HDF5_REPLAY_DRILL.md scripts/swarm_native_dependency_hdf5_replay_drill.sh scripts/e2e/swarm_native_dependency_hdf5_replay_drill_smoke.sh scripts/testdata/swarm_native_dependency_hdf5_replay_drill/cases.json
```
