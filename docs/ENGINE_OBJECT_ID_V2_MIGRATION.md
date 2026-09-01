# EngineObjectId SHA-256 V2 Migration

**Owning bead:** `bd-2y7`  
**Machine contract:** [`engine_object_id_derivation_contract_v2.json`](engine_object_id_derivation_contract_v2.json)  
**Current default:** `legacy_v1`  
**Target default:** `sha256_v2`  
**Migration state:** v2 derivation and explicit verification tooling implemented; default flip blocked on persisted-consumer versioning.

## Why this migration exists

`EngineObjectId` and `SchemaId` are used as security-critical, persisted
identities throughout policy, evidence, revocation, checkpoint, recovery, and
attestation surfaces. The original implementation describes those IDs as
collision-resistant but computes them with a home-grown SipHash-like function
that its own source labels non-cryptographic and recommends replacing for
production use.

That mismatch is not repaired safely by changing one function call. Existing
artifacts store only raw 32-byte IDs. If `derive_id` silently starts using a new
algorithm, old evidence and checkpoints will fail verification without carrying
enough information to distinguish an intentional version transition from data
corruption. Conversely, a verifier that simply tries both algorithms converts a
version boundary into an algorithm-confusion oracle.

The migration therefore uses an explicit two-version contract:

- `legacy_v1` exists only for artifacts whose persisted schema declares that
  version;
- `sha256_v2` is the cryptographic derivation for new identities once every
  persisted consumer can carry the version; and
- verification never falls back from one version to the other.

## Executable migration tool

The `franken_engine_object_id_migration` binary derives both versions for one
logical object or verifies one explicitly selected version.

Build and run:

```bash
cargo build --release --no-default-features \
  -p frankenengine-engine \
  --bin franken_engine_object_id_migration

cat > /tmp/object-id-request.json <<'JSON'
{
  "operation": "derive",
  "domain": "policy_object",
  "zone": "zone-a",
  "schema_definition_hex": "7b2274797065223a22506f6c696379227d",
  "canonical_bytes_hex": "7b22616c6c6f77223a747275657d"
}
JSON

./target/release/franken_engine_object_id_migration \
  --input /tmp/object-id-request.json
```

The response contains `legacy_v1` and `sha256_v2` records, including algorithm,
preimage contract, schema ID, and object ID. It also states the migration rule
that new artifacts use v2 while legacy verification must be selected from
persisted metadata.

Verification is explicit:

```json
{
  "operation": "verify",
  "version": "sha256_v2",
  "domain": "policy_object",
  "zone": "zone-a",
  "schema_definition_hex": "7b2274797065223a22506f6c696379227d",
  "canonical_bytes_hex": "7b22616c6c6f77223a747275657d",
  "expected_object_id_hex": "cdc31ac7ad5b4d68d7cbdae29179b3230608bd13afdfc641f2e1a4273913b545"
}
```

Exit codes:

| Code | Meaning |
|---:|---|
| `0` | Derivation completed, or the explicitly selected version verified. |
| `1` | The request was valid but the selected version did not match. No other version was attempted. |
| `2` | Invalid arguments, JSON, hex, empty canonical bytes, length overflow, or I/O failure. |

Errors are structured JSON on stderr. Successful derive/verify responses are
structured JSON on stdout unless `--output` names an atomically published file.

## V2 derivation contract

All variable-length fields are encoded with a four-byte big-endian length.

Schema ID:

```text
SHA-256(
  u32be(len("FrankenEngine.SchemaId.sha256.v2"))
  || "FrankenEngine.SchemaId.sha256.v2"
  || u32be(len(schema_definition))
  || schema_definition
)
```

Object ID:

```text
SHA-256(
  u32be(len("FrankenEngine.EngineObjectId.sha256.v2"))
  || "FrankenEngine.EngineObjectId.sha256.v2"
  || u32be(len(object_domain_tag))
  || object_domain_tag
  || u32be(len(zone))
  || zone
  || schema_id_32
  || u32be(len(canonical_bytes))
  || canonical_bytes
)
```

The version domain prevents cross-algorithm preimage ambiguity. Prefixing the
final canonical field removes the special-case “last field is unambiguous” rule
from v1 and makes every boundary independently parseable.

## Stable vectors

For:

- domain `policy_object` (`FrankenEngine.PolicyObject.v1`);
- zone `zone-a`;
- schema definition `{"type":"Policy"}`; and
- canonical object `{"allow":true}`:

| Version | Schema ID | Object ID |
|---|---|---|
| `legacy_v1` | `9704c8101b9f138f0d7ec78989eb1e1e0760f0756aeade43dee3975b8e73cce5` | `242c2cd17a8607149ec8dc88944aeb507a042208a522d21a9b58c112729e1ecd` |
| `sha256_v2` | `95dd1a7336da89398ea01216baed44a5170dd518af89379402227a3b12d1922a` | `cdc31ac7ad5b4d68d7cbdae29179b3230608bd13afdfc641f2e1a4273913b545` |

The binary unit tests and CLI integration tests pin these values. The vectors
were independently generated from the written preimage contract rather than
copied from the Rust implementation.

## Why the default has not flipped yet

The repository contains many serialized consumers of `EngineObjectId` and
`SchemaId`. A safe default flip requires each persisted schema to answer one
question without inference: **which derivation version produced this raw
32-byte value?**

Before changing the library default:

1. Generate a complete source/persistence inventory in both `franken-engine`
   and `franken-core`.
2. Classify each use as ephemeral, persisted, signed, hash-preimage-bearing, or
   replay-visible.
3. Add `derivation_version` to every persisted consumer, or document why the
   value cannot outlive a process.
4. Add explicit legacy replay/migration tests for retained evidence and
   checkpoints.
5. Implement the same v2 functions in both library copies and prove parity.
6. Change ordinary derivation and verification to v2 only.
7. Expose legacy verification through explicitly named APIs, never a fallback.
8. Regenerate golden vectors and evidence at one exact revision.

Until those steps land, documentation must not describe the current
`EngineObjectId` default as cryptographically collision-resistant. The v2 tool
is an observed migration aid, not evidence that all persisted identities have
already migrated.

## Verification

```bash
rustfmt --check --edition 2024 \
  crates/franken-engine/src/bin/franken_engine_object_id_migration.rs \
  crates/franken-engine/tests/engine_object_id_migration_cli.rs

cargo test --no-default-features -p frankenengine-engine \
  --bin franken_engine_object_id_migration

cargo test --no-default-features -p frankenengine-engine \
  --test engine_object_id_migration_cli

cargo clippy --no-default-features -p frankenengine-engine \
  --bin franken_engine_object_id_migration -- -D warnings
```

The next implementation slice is the machine-generated persisted-consumer
inventory and version-field migration, not the default flip itself.
