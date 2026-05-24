# PERF-H5.1 — Audit: does any production path round-trip a `TransportCertificate`?

- **Bead**: `bd-o4cbn.7.1` (PERF-H5.1 — Audit). Parent: `bd-o4cbn.7` (PERF-H5 — Transport-cert JSON roundtrip refactor, bench truthfulness).
- **Auditor**: GreenDeer
- **Date**: 2026-05-24
- **Scope**: every `TransportCertificate` occurrence in `crates/franken-engine`, classified production / test / bench.

## Question

Phase-1 profiling attributed ≈25% of the `transport_certificate_serialization`
bench self-time to the **deserialize** half (`serde_json::de::*`,
`deserialize_struct::<TransportCertificate>`, `deserialize_tuple::<ArrayVisitor<[u8;32]>>`).
H5 asks: is that deserialize step measuring real production work, or is it a
bench artifact? If a production path round-trips a cert, the bench's deserialize
step is justified and we keep it. Otherwise we refactor the bench (H5.2).

## Method

```bash
rg -n 'TransportCertificate' crates/franken-engine/src        # all references
rg -n 'serde_json::from_str|from_slice|from_value' \
    crates/franken-engine/src/transport_certificate_ledger.rs # deser sites
```

The type is defined in `transport_certificate_ledger.rs`. A whole-tree grep for
`TransportCertificate` returns **only** that file in `src/` — no other production
module names the type. Two files that matched a looser pattern
(`hostcall_batch_transport.rs`, `compression_residual_gate.rs`) were inspected
and are false positives: they use the unrelated `BatchTransportVerdict` and a
**separate** `ResidualLedger`/`ResidualLedgerEntry` type respectively; neither
deserializes a `TransportCertificate`.

The `#[cfg(test)] mod tests` block in `transport_certificate_ledger.rs` begins at
**line 1360**. Every `serde_json::from_str` in that file is at line ≥ 1410 — i.e.
**all deserialization is test-only**. There are **zero** deserialize calls before
line 1360 (no production deserialize).

## Audit table

| File:line | Symbol / pattern | Classification | Round-trips a cert? | Justification |
|---|---|---|---|---|
| `src/transport_certificate_ledger.rs:378` | `struct TransportCertificate` (derives `Serialize`/`Deserialize`) | production (type def) | no | Derive is for *emission* into evidence/ledger artifacts; deriving `Deserialize` does not imply a production read path. |
| `src/transport_certificate_ledger.rs:768` | `pub fn evaluate_transport(...) -> Result<TransportCertificate, _>` | production | no | Constructs a cert in-memory; no serde. |
| `src/transport_certificate_ledger.rs:827` | `pub fn build_residual_ledger(...)` | production | no | Aggregates certs; no serde. |
| `src/transport_certificate_ledger.rs:890` | `pub fn validate_ledger_consistency(...)` | production | no | Reads in-memory fields; no serde. |
| `src/transport_certificate_ledger.rs:925` | `pub fn franken_engine_transport_manifest() -> Vec<TransportCertificate>` | production | no | Returns an in-memory `Vec`; consumed in-process. |
| `src/transport_certificate_ledger.rs:1102` | `fn push_manifest_certificate(...)` | production | no | In-memory push. |
| `src/transport_certificate_ledger.rs:1172` | `build(certs: &[TransportCertificate])` (summary) | production | no | Borrows in-memory certs. |
| `src/transport_certificate_ledger.rs:1321` | `from_certificate(...)` (summary projection) | production | no | Reads in-memory fields. |
| `src/transport_certificate_ledger.rs:1410,1462,1518,1620,1928,1966,2063,2228,2361,2422` | `serde_json::from_str(...)` | **test** (`#[cfg(test)]`, line ≥1360) | yes (test only) | Serde round-trip coverage; not on any production path. |
| `benches/hot_paths.rs:336-338` | `to_string` → `from_str` → field read | **bench** | yes (bench only) | The bench under audit. See below. |
| `tests/transport_certificate_ledger_enrichment_integration.rs:850,1281,3185` | `serde_json::from_str(...)` | **test** | yes (test only) | Integration serde coverage; not production. |

### The bench round-trip (`benches/hot_paths.rs::real_runtime_certificate_digest`)

```rust
let certificate = evaluate_transport(/* ... */).expect("...");      // production API
let json = serde_json::to_string(&certificate).expect("...");        // serialize
let decoded: TransportCertificate =
    serde_json::from_str(&json).expect("...");                       // <-- deserialize half (H5 target)
ContentHash::compute(
    format!("{}:{}:{}:{}",
        decoded.certificate_id,            // already present on `certificate`
        decoded.outcome,                   // already present on `certificate`
        decoded.residual_fraction_millionths, // already present on `certificate`
        json)
    .as_bytes(),
)
```

`decoded` is used **only** to read three fields that are already available on the
original `certificate`. The `from_str` therefore reconstructs a value purely to
read back data that was never lost — it models no production behavior.

## Production serialization side (for completeness)

There is also **no production serialization** of a whole `TransportCertificate`.
The only `to_string`/`to_vec` calls before line 1360 are `String` conversions of
scalar `&str` fields (`cell_id.to_string()`, etc.) and `Vec::to_vec()` on a
reason slice — not `serde_json::to_string(&cert)`. Production constructs certs,
computes content hashes, and returns them as in-memory `Vec<TransportCertificate>`
for in-process consumption. Serde (both directions) is exercised only by tests and
this bench.

## Decision

**REFACTOR BENCH — proceed with H5.2.**

No production path round-trips (or even serializes) a `TransportCertificate`.
The bench's `from_str` deserialize step — ≈25% of measured self-time — is a pure
bench artifact: it reconstructs a value only to read fields already in hand. It
inflates the benchmark with work the shipped runtime never performs, so the bench
is **not truthful** as written.

### Recommended refactor for H5.2

- Drop the `from_str` round-trip; compute the digest directly from `certificate`'s
  fields.
- The `serde_json::to_string(&certificate)` may be **retained** only if H5.2 wants
  to model an actual emission/serialize cost (production does emit certs into
  evidence artifacts as bytes, even though it never reads them back as typed
  structs). If modeling emission is not the bench's intent, drop the serialize too
  and hash the in-memory fields. Recommend keeping the serialize (emission is real)
  and dropping only the deserialize (no production read path), matching H5's title.
- Add a dedicated round-trip **test** (H5.2 deliverable) so serde correctness
  coverage is not lost when the bench stops exercising it — note the existing
  `#[cfg(test)]` round-trips at `transport_certificate_ledger.rs:1928` and the
  integration tests already cover this, so the new test can be a focused assertion
  rather than net-new coverage.

## Acceptance check

- [x] Audit table populated (all `TransportCertificate` sites classified).
- [x] Decision recorded: **refactor bench** (proceed with H5.2).
