# Reproducibility Contract

This document defines the canonical artifact contract required to publish FrankenEngine claims as `observed` instead of intent-language.

A valid reproducibility bundle must include all three core files:
- `env.json`
- `manifest.json`
- `repro.lock`

If any required file is missing, stale, inconsistent, or invalid, publication must fail closed.

## Scope and Gate

This contract applies to all substantive `SECURITY`, `PERFORMANCE`, `COMPATIBILITY`, and `DETERMINISM` claims (see `docs/CLAIM_LANGUAGE_POLICY.md`).

A claim can pass the publication gate only when:
1. all three core files are present,
2. schemas validate,
3. canonical hashes match,
4. provenance links resolve,
5. deterministic replay checks pass.

## Artifact Schema Contracts

### `env.json`

Purpose: capture execution environment and runtime context used to generate results.

Required top-level keys:
- `schema_version`
- `schema_hash`
- `captured_at_utc`
- `project`
- `host`
- `toolchain`
- `runtime`
- `policy`

### `manifest.json`

Purpose: canonical index for claim metadata, inputs, outputs, and provenance references.

Required top-level keys:
- `schema_version`
- `schema_hash`
- `manifest_id`
- `generated_at_utc`
- `claim`
- `source_revision`
- `provenance`
- `artifacts`
- `inputs`
- `outputs`
- `canonicalization`
- `validation`
- `retention`

### `repro.lock`

Purpose: immutable lock of deterministic execution recipe and expected outputs.

Required top-level keys:
- `schema_version`
- `schema_hash`
- `generated_at_utc`
- `lock_id`
- `manifest_id`
- `source_commit`
- `determinism`
- `commands`
- `inputs`
- `expected_outputs`
- `replay`
- `verification`

## Version Compatibility Policy

- Schema IDs are semver-like (`*.v1`, `*.v2`, ...).
- Minor additive fields within the same schema major are allowed only when documented as optional.
- Removal/rename of required fields requires major version bump.
- Unknown required fields for a schema major are invalid.
- Unknown optional fields are ignored but preserved by tooling when re-emitted.

## Canonical Serialization and Hash Boundaries

Canonicalization rules:
- UTF-8 encoding only.
- JSON only for contract files.
- Lexicographic object-key ordering.
- Arrays retain declared order.
- LF (`\n`) newlines.
- No trailing whitespace.

Hashing rules:
- `sha256` over canonical file bytes.
- Hash boundaries are full-file content, not semantic subsets.
- `schema_hash` links schema identity to contract version.
- Invalid fields must cause validator rejection before hash acceptance.

## Provenance Linkage Rules

Every bundle must link to runtime evidence via stable identifiers:
- `trace_id`
- `decision_id`
- `policy_id`
- `replay_pointer`
- `evidence_pointer`
- receipt IDs (if applicable)

`manifest.json` is the authority for provenance linkage and must reference `env.json` and `repro.lock` hashes.

## Deterministic Validation CLI/API Contract

One-command verifier entry point:
- `frankenctl repro verify --bundle <path> --output <report.json>`

Machine-readable output contract:
- verdict: `pass|fail`
- `bundle_id`
- `validated_at_utc`
- deterministic per-check records with `component`, `event`, `outcome`, `error_code`

Stable error-code taxonomy:
- `FE-REPRO-0001` missing required file
- `FE-REPRO-0002` schema validation failure
- `FE-REPRO-0003` canonicalization mismatch
- `FE-REPRO-0004` digest mismatch
- `FE-REPRO-0005` provenance link missing or inconsistent
- `FE-REPRO-0006` replay command failed
- `FE-REPRO-0007` stale policy/environment window
- `FE-REPRO-0008` disallowed override/degraded-mode attempt

## Fail-Closed and Degraded Mode Policy

Default behavior is fail closed:
- Missing core artifacts: fail.
- Partial manifests: fail.
- Stale policy/environment snapshots beyond allowed window: fail.
- Output hash mismatch: fail.

Degraded mode:
- Allowed only for local diagnostics.
- Must never promote claim status to `observed`.
- Requires explicit operator override artifact with rationale and signer.
- Override cannot suppress `FE-REPRO-0001` through `FE-REPRO-0005`.

## CI Publication Gate Contract

CI must block publication when any contract check fails.

Minimum CI gate behavior:
1. Validate bundle schemas.
2. Recompute and compare all declared hashes.
3. Run locked commands in deterministic mode.
4. Verify `expected_outputs` hashes.
5. Emit verifier report artifact and stable structured events.

## Neutral Verifier Flow

Third-party verification flow:
1. Obtain bundle directory.
2. Run `scripts/third_party_repro_lock_verifier.sh --lock <path>/repro.lock --report <report.json>`.
3. Confirm report verdict is `pass`.
4. Confirm the report lists the locked command sequence and source commit.
5. Re-run to confirm deterministic identical verdict and output hashes.

When a release package only needs to prove that a third party can derive the
replay plan before spending remote-build budget, use `--plan-only`; publication
still requires a non-plan verifier report with verdict `pass`.

## Retention and Rotation Policy

- Keep reproducibility bundles for at least 365 days for published claims.
- Keep high-impact security/replay claim bundles for at least 730 days.
- Rotation may archive cold bundles but must preserve hash-addressable retrieval.
- Deletion is disallowed while any open audit, incident, or release dispute references the bundle.

## Template Locations

- `docs/templates/env.json.template`
- `docs/templates/manifest.json.template`
- `docs/templates/repro.lock.template`

## Operator Checklist

Before publishing a claim:
1. Replace all template placeholders.
2. Validate bundle with one-command verifier.
3. Confirm all hashes match and provenance links resolve.
4. Attach verifier report + bundle path to claim publication context.
5. If validation fails, downgrade claim to intent-language.
