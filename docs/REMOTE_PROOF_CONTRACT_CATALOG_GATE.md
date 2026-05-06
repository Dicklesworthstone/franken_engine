# Remote Proof Contract Catalog Gate

`scripts/remote_proof_contract_catalog_gate.sh` validates that remote-proof
control-plane surfaces still publish coherent contracts, implementation
scripts, smoke scripts, operator docs, and upstream schema links.

The gate is intentionally fixture-driven. It does not run Cargo, query `rch`, or
fetch worker artifacts. It reads a surface manifest, checks the repo-local files
declared there, and emits a deterministic catalog report.

## Usage

```bash
./scripts/remote_proof_contract_catalog_gate.sh \
  --surface-manifest-json artifacts/remote_proof_surface_manifest.json \
  --output-dir /tmp/remote-proof-contract-catalog
```

The optional `--repo-root` flag points repo-relative manifest paths at a
different root for fixture validation. Operator usage should normally rely on
the default repository root.

## Manifest

The input manifest uses schema version
`franken-engine.remote-proof-contract-catalog-manifest.v1`.

Each surface declares:

- `surface_id`
- `contract_json`
- `implementation_script`
- `smoke_script`
- `doc_path`
- `emitted_schema`
- `upstream_schemas[]`

Paths must be relative to the selected repo root and cannot use parent
traversal. Upstream schemas must either be emitted by another listed surface or
declared in `external_schemas[]`.

## Report Contract

The emitted `contract_catalog_report.json` uses schema version
`franken-engine.remote-proof-contract-catalog-report.v1`.

Key fields:

- `catalog_id`
- `catalog_decision`
- `reason`
- `surface_count`
- `finding_count`
- `surfaces[]`
- `findings[]`
- `hash_basis.catalog_hash`
- `upstream_artifact_paths`
- `artifact_paths`

## Decision Rules

The catalog passes only when all of these hold:

- each surface has a unique `surface_id`
- every contract JSON exists, parses, and declares `schema_version`
- every contract declares `required_inputs`, `required_artifacts`, and
  `determinism`
- contract schema versions and emitted schemas are unique
- implementation scripts mention their required CLI inputs
- smoke scripts expose `check` and `selftest` modes
- operator docs mention the implementation script, emitted schema, and required
  artifacts
- all upstream schemas are known through another surface or `external_schemas[]`

Any violation is fail-closed with exit code `42`.

## Artifacts

Each run emits:

- `contract_catalog_report.json`
- `surface_manifest.normalized.json`
- `catalog_entries.jsonl`
- `commands.txt`
- `events.jsonl`
- `report.md`

## Validation

```bash
bash -n scripts/remote_proof_contract_catalog_gate.sh
bash -n scripts/e2e/remote_proof_contract_catalog_gate_smoke.sh
bash scripts/e2e/remote_proof_contract_catalog_gate_smoke.sh check
bash scripts/e2e/remote_proof_contract_catalog_gate_smoke.sh selftest
```
