# RGC Persistent Cache Contract V1

## Purpose

`bd-1lsy.7.10.1` turns the existing `ModuleCache` behavior into an explicit
content-addressed contract instead of an implicit in-memory convenience.

The core cache implementation already provides deterministic module keys,
source/policy/trust invalidation, state hashing, snapshot merge, and
fail-closed revocation behavior. This contract layer adds the missing operator
surface:

- richer content-addressed cache keys that include configuration, dependency,
  transform, runtime, and engine-version context
- stable receipts that product, benchmark, and replay tooling can all consume
- deterministic rollback plans for corrupt or contradictory cache state
- replayable artifact bundles instead of ad hoc cache debugging

## Contract Artifacts

The emitted bundle must contain these deterministic artifacts:

- `persistent_cache_contract.json`
- `run_manifest.json`
- `events.jsonl`
- `commands.txt`
- `trace_ids.json`
- `env.json`
- `manifest.json`
- `repro.lock`
- `summary.md`

`persistent_cache_contract.json` is the machine-readable source of truth. It
records:

- the stable cache-key fields
- invalidation rules
- consumer routes for product, benchmark, and replay tooling
- sample verified receipts
- corruption and rollback scenarios

## Key Fields

The content-addressed cache key must bind at least:

- `module_id`
- `source_hash`
- `policy_version`
- `trust_revision`
- `config_fingerprint`
- `dependency_graph_hash`
- `transform_profile`
- `runtime_mode`
- `engine_version_marker`

That keeps cache reuse honest. If any of those change, reuse must fail closed
instead of silently pretending the old artifact still matches the current
execution context.

## Consumer Routes

The default contract exposes three consumers:

- `product`: explain cache reuse or bypass to operator-facing flows
- `benchmark`: prove which cache state and policy version backed a result
- `replay`: stitch receipts back into deterministic run manifests and
  decision traces

## Verification

Heavy verification is `rch`-only:

```bash
./scripts/run_persistent_cache_contract_suite.sh ci
./scripts/e2e/persistent_cache_contract_replay.sh ci
```

The implementation surface lives in:

- `crates/franken-engine/src/module_cache.rs`
- `crates/franken-engine/src/persistent_cache_contract.rs`
- `crates/franken-engine/src/bin/franken_persistent_cache_contract.rs`
- `crates/franken-engine/tests/persistent_cache_contract.rs`

The machine-readable fixture lives in:

- `docs/rgc_persistent_cache_contract_v1.json`

Artifacts are emitted under `artifacts/persistent_cache_contract/<timestamp>/`.
If required artifact names, consumer routes, scenario IDs, or key fields
change, update the contract fixture explicitly instead of letting the suite
drift.
