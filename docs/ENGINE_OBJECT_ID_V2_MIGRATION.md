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
- `sha256_v2` is available through explicitly versioned APIs for consumers
  whose persisted schemas and verification paths carry the version; the
  unversioned library default remains blocked on the remaining consumers; and
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

Work in dependency order rather than treating new modules as migration completion:

1. Preserve and test the existing v2 derivation and persisted-wire APIs in
   `engine_object_id/versioned.rs` and `engine_object_id/wire.rs` in both
   library copies. Source parity is necessary, not a substitute for execution.
2. Run the existing consumer guard across `franken-engine`, `franken-core`,
   and `franken-extension-host`. Investigate serialized, signed,
   hash-preimage-bearing, and replay-visible uses, including aliases and
   wrappers that a lexical scan may miss.
3. Migrate one persisted consumer and its real read/write call sites at a time.
   Carry the algorithm tag in the schema and bind it into signed or hashed
   preimages. Keep legacy provenance explicit; never guess an algorithm.
4. Verify token authority and delegation using trusted verifier context, then
   test the consuming execution/replay path. A v2 adapter existing in a module
   does not prove that a runtime caller uses it.
5. Replay retained legacy evidence and checkpoints through explicit legacy
   APIs. Preserve historical vectors; add independently derived v2 vectors.
   Do not regenerate expected outputs merely to make a test pass.
6. Only after consumer coverage, parity, positive/negative execution tests,
   and an explicit default-flip review succeed, change the ordinary default
   and its machine contract together. Record the exact revision and commands.

### Linked verification boundaries

| Boundary | Existing source of truth | What must be established before proceeding |
|---|---|---|
| Identity bytes | Derivation contract and `engine_object_id/versioned.rs` | Domain, zone, schema, canonical bytes, and algorithm agree. |
| Persisted identity | `engine_object_id/wire.rs` | The algorithm tag survives serialization; legacy reads are explicit. |
| Signed authority | `capability_token/versioned.rs` | Identity and signature verify; audience, time, epoch, checkpoint, and revocation constraints hold. |
| Delegated authority | `delegation_chain/versioned.rs` | The root is authorized, each link verifies, capabilities only attenuate, and the leaf has the requested capability. |
| Runtime adoption | Actual consumer call sites and execution/replay tests | The verified authority is used by the intended runtime path, not merely demonstrated by a disconnected adapter test. |

**Identity is not authority, and a serialized proof is not automatically a fresh
verification result.** In `VersionedDelegationVerificationContext`, provide the
current tick and epoch, checkpoint and revocation sequence frontiers, accepted
tagged checkpoint IDs and revocation heads, authorized roots, depth limit, and
required zone from trusted verifier state. The root/checkpoint builder methods
do not advance the clock or sequence frontiers. Never copy a presented token's
minimum frontier into production verifier state to make it pass.

Every rejection test should begin with a successfully verified positive control,
change one relevant condition, and assert the exact rejection category and link
index. Capability amplification tests must use a correctly signed child so that
an identity or signature failure cannot masquerade as attenuation enforcement.

### Machine-readable migration decision

Use the existing report rather than a hand-maintained consumer count:

```bash
python3 scripts/e2e/engine_object_id_versioning_guard_smoke.py
python3 scripts/check_engine_object_id_derivation_versioning.py \
  --output /tmp/engine-object-id-consumer-report.json
```

Read `decision`, `violations`, `scan_roots`, `scanned_source_file_count`,
`blocking_consumer_type_count`, and `blocking_consumers` together. Findings
include source paths, type names, line locations, and blocking reasons. Missing,
empty, unreadable, or skipped source trees are inspection failures, not evidence
of zero consumers. The guard rejects them rather than emitting a readiness
report. Do not reuse an older report after a command fails; retain the command's
exit status and associate successful output with the checkout revision.

| Result | Meaning and next action |
|---|---|
| `allow_current_posture`, `default_flip_allowed: false` | The existing posture is allowed; migration is still blocked. Work on the reported consumers. |
| `fail_closed`, or exit `2` without a new report | Inspection, contract, or parity failed. Fix that cause before inferring migration readiness. |
| `default_flip_allowed: true` | The guard found no modeled blockers. This is a prerequisite for explicit review, not authorization to flip the default automatically. |

`--require-ready` intentionally returns exit `1` when a valid scan still reports
blocked readiness; that is distinct from an inspection failure. The scanner is
a conservative source inventory, not a Rust type checker or a proof that every
transitive persisted consumer has been migrated.

Until those steps land, documentation must not describe the current
`EngineObjectId` default as cryptographically collision-resistant. The v2 tool
is an observed migration aid, not evidence that all persisted identities have
already migrated.

## Verification

```bash
set -euo pipefail

python3 scripts/e2e/engine_object_id_versioning_guard_smoke.py
python3 scripts/check_engine_object_id_derivation_versioning.py \
  --output /tmp/engine-object-id-consumer-report.json

for module in engine_object_id capability_token delegation_chain; do
  cargo test --no-default-features -p frankenengine-engine \
    --lib "${module}::"
done
cargo test --no-default-features -p frankenengine-core \
  --lib 'engine_object_id::'

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

The existing `engine-object-id-v2-migration.yml` workflow runs the focused
library and CLI checks on relevant direct-to-`main` pushes as well as pull
requests. Its library checks include the nested identity, token, and delegation
modules; its contract job uses the shared guard instead of assuming that legacy
implementations remain inline in the top-level Rust files. These focused checks
do not replace the repository-wide formatting, check, Clippy, and test gates in
`AGENTS.md`.

Record test status as executed/pass, executed/fail, or not executed, together
with the revision and command. A queued CI run is not a pass. For remote bead
operations, match the result's `request_id`, `bead_id`, and source revision to
the requested operation before changing the reported task status; a successful
result for a previous request is not confirmation of the current request.

The next implementation slice is a real persisted-consumer migration selected
from a fresh inventory and the live bead dependency graph, with its runtime
caller and replay coverage, not the default flip itself.
