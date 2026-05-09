# SWARM_NATIVE_DEPENDENCY_ROUTING_TRACK_CLOSEOUT

The `bd-sqm14` native dependency routing track is a fixture-first validation
control plane for C-backed Rust path dependencies such as HDF5. The track
preserves the observed `hdf5-metno-sys` worker gap as deterministic evidence so
agents can distinguish source failures from validation environment blockers.

The closeout verifier is `scripts/swarm_native_dependency_track_closeout.sh`.
It checks:

- child bead artifact inventory
- expected dependency ordering from contract to requirement inference, worker
  probes, route planning, ABI safety, operator status, HDF5 replay, and planner
  integration
- `bv --robot-insights` cycle-break evidence
- focused fixture and golden smoke commands introduced by the track

The verifier does not run Cargo or RCH. Live worker proof is optional operator proof because HDF5 package state can drift after the fixture timestamp.

## Child Artifact Map

- `bd-sqm14.1`: contract docs, JSON contract, contract smoke, contract cases
- `bd-sqm14.2`: requirement inference script, requirement map, smoke, cases
- `bd-sqm14.3`: worker probe normalizer, worker probe contract, smoke, cases
- `bd-sqm14.4`: route planner, route planner contract, smoke, cases
- `bd-sqm14.5`: ABI cache ledger, ABI contract, smoke, cases
- `bd-sqm14.6`: operator status script, operator docs, smoke, cases
- `bd-sqm14.7`: HDF5 replay drill, drill docs, smoke, cases
- `bd-sqm14.9`: validation planner native advisory integration and native
  dependency golden outputs
- `bd-sqm14.8`: this closeout verifier, closeout docs, smoke, cases

## Validation

```bash
jq empty scripts/testdata/swarm_native_dependency_track_closeout/cases.json
bash -n scripts/swarm_native_dependency_track_closeout.sh
bash -n scripts/e2e/swarm_native_dependency_track_closeout_smoke.sh
bash scripts/e2e/swarm_native_dependency_track_closeout_smoke.sh check
bash scripts/e2e/swarm_native_dependency_track_closeout_smoke.sh selftest
git diff --check -- docs/SWARM_NATIVE_DEPENDENCY_ROUTING_TRACK_CLOSEOUT.md scripts/swarm_native_dependency_track_closeout.sh scripts/e2e/swarm_native_dependency_track_closeout_smoke.sh scripts/testdata/swarm_native_dependency_track_closeout/cases.json
```

No broad Rust gates are required for this closeout bead because it adds only
shell, JSON fixture, and Markdown artifacts.
