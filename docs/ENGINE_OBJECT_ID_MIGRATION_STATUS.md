# EngineObjectId V2 Migration Status

**Owning bead:** `bd-2y7`  
**Current library default:** `legacy_v1`  
**Target library default:** `sha256_v2`  
**Current state:** v2 derivation and explicit verification tooling implemented; default flip blocked by unversioned persisted consumers.

## Delivered

- Machine-readable v1/v2 preimage and migration contract:
  `docs/engine_object_id_derivation_contract_v2.json`.
- Operator/architecture guide:
  `docs/ENGINE_OBJECT_ID_V2_MIGRATION.md`.
- Agent-facing JSON migration binary:
  `franken_engine_object_id_migration`.
- Stable independently generated vectors for legacy-v1 and SHA-256-v2.
- Explicit verification version with no cross-version fallback.
- Structured mismatch/error exit codes and atomic output-file publishing.
- Black-box CLI tests and current-runtime legacy vector parity tests.
- Source-wide persisted-consumer guard:
  `scripts/check_engine_object_id_derivation_versioning.py`.
- Both-direction guard drill proving:
  - legacy is allowed while unversioned persisted consumers remain;
  - an early v2 default flip fails closed; and
  - v2 becomes eligible only after persisted consumers declare a version.
- Focused workflows for derivation vectors, CLI behavior, legacy parity, and
  persisted-consumer default-flip protection.

## Why the default remains legacy-v1

The raw `EngineObjectId` and `SchemaId` types contain only 32 bytes. Existing
persisted evidence, checkpoints, manifests, revocations, and signed preimages do
not uniformly carry the algorithm that produced those bytes. Flipping the
default now would make legacy artifacts appear corrupt; accepting either
algorithm heuristically would create algorithm confusion.

The present posture is therefore intentionally fail-closed:

- new v2 IDs can be derived, compared, and verified explicitly;
- legacy IDs can be verified only when legacy-v1 is selected explicitly; and
- the library default cannot change while the consumer guard reports
  unversioned persisted or signed consumers.

## Remaining work before default flip

- [ ] Preserve a deterministic repository-wide consumer inventory at an exact
      revision.
- [ ] Classify every consumer as ephemeral or persisted/signed.
- [ ] Add `derivation_version` to every persisted/signed schema.
- [ ] Add explicit legacy replay/migration coverage for retained artifacts.
- [ ] Implement SHA-256-v2 derivation in both `franken-engine` and
      `franken-core` library modules with byte-identical vectors.
- [ ] Make ordinary derivation and verification v2-only.
- [ ] Expose legacy-v1 solely through explicitly named compatibility APIs.
- [ ] Regenerate affected golden vectors and evidence bundles.
- [ ] Reconcile all collision-resistance wording with current evidence.
- [ ] Run workspace checks and claim gates at one exact revision.

## Verification commands

```bash
python3 scripts/e2e/engine_object_id_versioning_guard_smoke.py
python3 scripts/check_engine_object_id_derivation_versioning.py \
  --output /tmp/engine-object-id-consumers.json

cargo test --no-default-features -p frankenengine-engine \
  --bin franken_engine_object_id_migration
cargo test --no-default-features -p frankenengine-engine \
  --test engine_object_id_migration_cli
cargo test --no-default-features -p frankenengine-engine \
  --test engine_object_id_legacy_vector_parity
```

A green result means the staged migration behaves correctly and the current
legacy posture is internally consistent. It does **not** mean the runtime
library default has already migrated to SHA-256-v2.
