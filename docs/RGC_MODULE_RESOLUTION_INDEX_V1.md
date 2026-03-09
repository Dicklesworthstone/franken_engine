# RGC Module Resolution Index V1

Status: active
Primary bead: bd-1lsy.5.8.1
Track id: RGC-406A
Machine-readable contract: `docs/rgc_module_resolution_index_v1.json`

## Purpose

`RGC-406A` defines a deterministic startup-friendly index layer for the
TypeScript/package resolver so common package-name, exact export, and hot
subpath lookups can avoid repeated map scans without changing resolver
semantics.

This contract requires stable workspace and index fingerprints, replayable
artifact bundles, and explicit machine-readable fallback reasons whenever an
artifact is stale, unverifiable, or unsuitable for indexed lookup.

## Index Construction

The lane produces three cooperating artifact families:

- a package-name ART report for deterministic package-root lookup
- an export-map MPHF-style catalog for exact export keys
- a hot-subpath MPHF-style catalog for exact `./subpath` entries

Wildcard export patterns remain part of the catalog for diagnostics, but they
are not accelerated by the exact-key index. When a request depends on wildcard
matching, the runtime must fall back to the incumbent resolver path instead of
guessing.

Stable identity is derived from:

- resolver config fingerprint
- registered file-set fingerprint
- package-definition fingerprint
- package ART report fingerprint
- export/subpath catalog fingerprint

## Validation and Fallback

The resolver must reject index artifacts when any of the following holds:

- artifact age exceeds the configured freshness window
- workspace fingerprint no longer matches the live resolver state
- serialized report fingerprints no longer match the recorded identity report

Fallback is fail-closed and machine-readable. Required reason ids include:

- `artifact_age_exceeded`
- `workspace_fingerprint_mismatch`
- `index_fingerprint_mismatch`
- `collision_search_exhausted`
- `unsupported_wildcard_export`

On rejection or unsupported indexed lookup, the resolver must fall back to the
incumbent package-resolution path with no semantic drift in the final outcome.

## Artifact Contract

Each index evidence bundle must emit:

- `module_art_index_report.json`
- `export_map_hash_catalog.json`
- `module_index_identity_report.json`
- `run_manifest.json`
- `events.jsonl`
- `commands.txt`
- `trace_ids.json`
- `step_logs/`

`run_manifest.json` must include schema version, scenario id, generation time,
workspace fingerprint, index fingerprint, validation result, and artifact path
mappings.

## Operator Verification

```bash
jq empty docs/rgc_module_resolution_index_v1.json

./scripts/run_rgc_module_resolution_index_suite.sh ci
./scripts/e2e/rgc_module_resolution_index_replay.sh ci

rch exec -- env RUSTUP_TOOLCHAIN=nightly CARGO_TARGET_DIR=/data/projects/franken_engine/target_rch_module_resolution_index \
  cargo test -p frankenengine-engine --test module_resolution_index
```
