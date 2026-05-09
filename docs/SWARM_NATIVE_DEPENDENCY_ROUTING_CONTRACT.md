# SWARM_NATIVE_DEPENDENCY_ROUTING_CONTRACT

`docs/swarm_native_dependency_routing_contract_v1.json` defines the
contract-only truth surface for native system dependencies that can make an
`rch` remote validation fail before the intended Rust test or check executes.

This bundle extends existing worker capability and remote proof contracts:

- `docs/SWARM_CAPABILITY_AFFINITY_ROUTING_CONTRACT.md`
- `docs/SWARM_WORKER_CAPABILITY_TOOLCHAIN_NORMALIZER.md`
- `docs/RCH_VALIDATION_PREFLIGHT_CONTRACT_V1.md`
- `docs/RCH_WORKER_TRUTH_PARITY_LEDGER.md`
- `scripts/e2e/rch_validation_preflight_contract_smoke.sh`
- `scripts/e2e/rch_worker_truth_parity_ledger_smoke.sh`

It is evidence-only and advisory-only. It must not be described as a live
worker repair surface, package installation surface, automatic task rerouter,
queue-policy mutator, Agent Mail mutator, or bead mutation surface.

## Required Preserved Inputs

The future native dependency routing bundle must preserve four required inputs:

- `native_requirement_bundle_json`
- `worker_native_probe_snapshot_json`
- `rch_failure_log_excerpt_json`
- `validation_command_context_json`

Together these sources must preserve the minimum advisory subject:

- `validation_id`
- `command`
- `cargo_package`
- `path_dependency_closure`
- `dependency_id`
- `native_package_name`
- `probe_kind`
- `required`
- `candidate_worker_ids`
- `worker_id`
- `probe_command`
- `probe_status`
- `observed_version`
- `abi_fingerprint`
- `probe_timestamp`
- `freshness_state`
- `contamination_state`
- `reason_codes`

Missing required preserved inputs fail closed.

## Optional Preserved Inputs

Optional supporting inputs may remain absent without invalidating the advisory,
but they must degrade confidence instead of upgrading the result:

- `worker_capability_snapshot_json`
- `worker_toolchain_snapshot_json`
- `operator_status_snapshot_json`

## Native Dependency Families

The initial contract must be able to express at least these native dependency
families:

- `hdf5` for `hdf5-metno-sys` and related `frankenpandas` validation closure
- `sqlite3` for `libsqlite3-sys`
- `openssl` for `openssl-sys`
- `zstd` for `zstd-sys`
- `unknown_build_script_native_dependency` for diagnostics that mention a
  native prerequisite but do not map to a known family

Each family must carry the expected `pkg-config` package names, optional
environment roots such as `HDF5_DIR`, required header names when known, and the
required probe kinds.

## Probe Kinds

- `pkg_config_modversion`
- `header_presence`
- `library_linkability`
- `env_root`
- `build_script_diagnostic`

Probe commands are read-only evidence commands. The contract must not prescribe
package installation, worker mutation, automatic worker drain, or automatic
queue rerouting.

## Truth States

- `confirmed`: required native dependency evidence is fresh, coherent, and
  uncontaminated for the candidate worker
- `degraded`: required evidence is coherent enough to keep the advisory
  readable, but optional support or non-critical probes are missing
- `blocked`: required evidence proves that at least one candidate worker lacks a
  required native dependency
- `contaminated`: local fallback or non-remote evidence contaminates the remote
  validation claim
- `unknown`: evidence is insufficient or ambiguous and must not be promoted to a
  healthy route

## Decision Language

- `pass`: native dependency evidence is safe to use as advisory routing input
- `degraded`: advisory routing remains readable with reduced confidence
- `blocked`: required native dependency evidence blocks the candidate route
- `fail_closed`: malformed, stale, contradictory, contaminated, or unsupported
  evidence invalidates the advisory

## Required Reason Codes

- `required_native_dependency_present`
- `hdf5_required_present`
- `hdf5_required_missing`
- `optional_native_dependency_absent`
- `missing_required_native_package_metadata`
- `missing_native_headers`
- `pkg_config_unavailable`
- `stale_worker_probe`
- `contradictory_pkg_config_header_evidence`
- `local_fallback_contaminated`
- `unsupported_worker_mutation_advice`
- `ambiguous_build_script_diagnostic`

## Fail-Closed Rules

- Missing required preserved inputs fail closed.
- A required native package with missing `pkg-config` metadata blocks the route.
- Missing required headers block the route.
- Stale worker probe snapshots fail closed unless the dependency is explicitly
  optional and the output is downgraded to `degraded`.
- Contradictory `pkg-config` and header evidence fails closed.
- Local fallback contamination fails closed and invalidates remote-only
  validation proof.
- Unsupported worker mutation advice fails closed. The correct output is a
  blocker receipt, not package installation instructions.
- Ambiguous build-script diagnostics fail closed until the requirement map can
  represent the native dependency family.

## Expected Outputs

Downstream implementation beads must eventually preserve at least:

- `native_dependency_requirement_bundle.json`
- `worker_native_probe_snapshot.json`
- `native_dependency_routing_advisory.json`
- `events.jsonl`
- `commands.txt`
- `summary.md`

The future advisory bundle is expected to expose:

- `native_dependency_advisory_id`
- `truth_state`
- `decision`
- `source_artifacts`
- `reason_codes`
- `dependency_requirements`
- `worker_probe_summary`
- `candidate_worker_summary`
- `fail_closed_reason`
- `artifact_paths`

## Structured Events

Every event emitted by downstream scripts must include:

- `trace_id`
- `validation_id`
- `worker_id`
- `dependency_id`
- `component`
- `event`
- `outcome`
- `error_code`

## Proof Cases

The contract language is written to support at least these fixture-fed proof
cases:

- `hdf5_required_present`
- `hdf5_required_missing`
- `optional_native_dependency_absent`
- `stale_worker_probe`
- `contradictory_pkg_config_header_evidence`
- `local_fallback_contaminated`

These cases must stay advisory-only and must not imply worker mutation, live
queue mutation, or automatic rerouting.

## Current Evidence Note

The contract is grounded in the validation blocker observed while working
around `bd-bzbcn`: one `rch` worker returned no HDF5 evidence for the
`frankenpandas -> hdf5-metno-sys` closure while other workers reported
`pkg-config hdf5 1.14.5`. That difference is a worker native dependency gap,
not proof that the Rust source patch failed.

## Validation

```bash
jq empty docs/swarm_native_dependency_routing_contract_v1.json
jq empty scripts/testdata/swarm_native_dependency_contract/cases.json
bash -n scripts/e2e/swarm_native_dependency_contract_smoke.sh
bash scripts/e2e/swarm_native_dependency_contract_smoke.sh check
bash scripts/e2e/swarm_native_dependency_contract_smoke.sh selftest
git diff --check -- docs/SWARM_NATIVE_DEPENDENCY_ROUTING_CONTRACT.md docs/swarm_native_dependency_routing_contract_v1.json scripts/e2e/swarm_native_dependency_contract_smoke.sh scripts/testdata/swarm_native_dependency_contract/cases.json
```
