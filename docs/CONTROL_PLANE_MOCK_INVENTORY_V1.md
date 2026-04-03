# Control-Plane Mock Inventory V1

Bead: `bd-3nr.1.1.1`

This surface turns the canonical control-plane mock seam inventory into a replayable operator artifact bundle. It exists so downstream beads can consume a stable inventory contract instead of re-running ad hoc scans or reading the Rust source directly.

The exposure-model decision and current-consumer inventory for `bd-2muur.3.1` live in [`CONTROL_PLANE_TEST_SUPPORT_MODEL_V1.md`](./CONTROL_PLANE_TEST_SUPPORT_MODEL_V1.md).

## Scope

- Emits the canonical `asupersync_residual_mock_inventory.json` inventory.
- Derives a `production_mock_seam_matrix.json` with only must-fix production seams and architectural issues.
- Records `trace_ids.json`, `run_manifest.json`, `events.jsonl`, `summary.md`, `env.json`, `repro.lock`, and `step_logs/step_001_inventory.log`.
- Preserves the exact invocation in `commands.txt`.

## Operator Entry Points

Direct binary:

```bash
rch exec -- cargo run -p frankenengine-engine --bin franken_control_plane_mock_inventory -- --out-dir artifacts/control_plane_mock_inventory/manual
```

Workspace-root override:

```bash
rch exec -- cargo run -p frankenengine-engine --bin franken_control_plane_mock_inventory -- --out-dir artifacts/control_plane_mock_inventory/manual --workspace-root /data/projects/franken_engine
```

`rch`-backed suite:

```bash
./scripts/run_control_plane_mock_inventory.sh ci
```

Replay wrapper:

```bash
./scripts/e2e/control_plane_mock_inventory_replay.sh ci
```

## Artifact Contract

- `asupersync_residual_mock_inventory.json`: canonical `MockInventory` snapshot.
- `production_mock_seam_matrix.json`: must-fix production seam matrix for follow-on remediation beads.
- `trace_ids.json`: deterministic trace and decision IDs plus inventory and matrix hashes.
- `run_manifest.json`: top-level execution outcome and relative artifact paths.
- `events.jsonl`: machine-readable event stream for inventory start, must-fix seam classification, architectural issue classification, and completion.
- `summary.md`: operator-facing markdown summary.
- `env.json`: workspace and toolchain capture for replay provenance.
- `repro.lock`: replay contract with the binary command.

## Verification

The intended verification path is the `rch` suite, which runs:

- `cargo check -p frankenengine-engine --lib --bin franken_control_plane_mock_inventory --test control_plane_mock_inventory_integration`
- focused lib and integration tests for the bundle and binary surface
- `cargo build -p frankenengine-engine --bin franken_control_plane_mock_inventory`
- `cargo clippy -p frankenengine-engine --lib --bin franken_control_plane_mock_inventory --test control_plane_mock_inventory_integration -- -D warnings`

`summary.md`, `run_manifest.json`, and `suite_commands.txt` under the artifact directory are the operator proof points to attach to bead progress updates.
