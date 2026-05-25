# PERF-ALIEN-1.1 — Merkle-Batched Session Signing: Shape & Canonicalization

**Bead:** `bd-o4cbn.9.1` (parent `bd-o4cbn.9`, PERF-ALIEN-1). **Status:** design only —
implementation is `bd-o4cbn.9.2` (`SessionSigningBatch` + verify path).

## Motivation

The evidence ledger signs one ed25519 signature per evidence entry. Under load that
is one curve operation per entry. **Merkle batching** lets a session accumulate N
entries, build a Merkle tree over their canonical hashes, and sign the **root once** —
turning N signatures into 1 signature + N cheap inclusion proofs. Each entry remains
independently verifiable against the signed root via its O(log N) inclusion proof.

This document pins the byte-level shapes so the implementation, the verifier, and any
external auditor agree exactly. **Canonical encoding feeds every hash here**, so a
1-byte ambiguity would break replay and evidence integrity — every framing below is
length-prefixed and domain-separated.

## Project primitives this design binds to

- **Hash:** `hash_tiers::ContentHash::compute(&[u8]) -> ContentHash([u8; 32])` — SHA-256,
  the project's Tier-2 content hash. All hashes below are this 32-byte SHA-256.
- **Canonical bytes:** `deterministic_serde::encode_value(&CanonicalValue) -> Vec<u8>`
  (equivalently `encode_value_into(buf, value)` for buffer reuse, per `bd-o4cbn.5.3`).
  This is the deterministic, length-prefixed canonical serialization.
- **Schema binding:** `SchemaId` / `SchemaHash` (32 bytes) identifies the entry schema.
- **Root signing:** the ed25519 key infrastructure in `evidence_ledger`
  (`DEFAULT_EVIDENCE_SIGNING_KEY`, deterministic `SigningKey`). The Merkle **root**, not
  each entry, is signed.

## 1. Leaf encoding

```text
leaf_hash = SHA256( 0x00 || u32_be(len) || canonical )
where  canonical = encode_value(entry)
       len       = canonical.len()   (clamped to u32::MAX, matching the encoder's own clamp)
```

- The leading `0x00` is the **leaf domain-separation byte** (RFC 6962 §2.1).
- The `u32_be(len)` outer length prefix is mandatory under the project's framing
  discipline: it guarantees no leaf's `(0x00 || len || canonical)` preimage can be a
  prefix of another, independent of `encode_value`'s internal prefixes. It also lets a
  streaming verifier frame the entry without trusting an external length.

## 2. Internal node encoding

```text
internal_hash = SHA256( 0x01 || left_hash || right_hash )
```

- `left_hash` and `right_hash` are each exactly 32 bytes, so no length prefix is needed
  (fixed-width concatenation is unambiguous).
- The leading `0x01` is the **internal domain-separation byte** (RFC 6962 §2.1). Because
  leaves are hashed with a `0x00` prefix and internal nodes with `0x01`, no internal
  hash preimage can ever collide with a leaf hash preimage — this is the standard
  second-preimage defense.

## 3. Tree shape canonicalization (RFC 6962, **no leaf duplication**)

The tree is the RFC 6962 Merkle Tree Hash (MTH), defined recursively over the ordered
list of leaf inputs `d[0..n]`:

```text
MTH({})            = SHA256("")                       # empty tree: hash of the empty string
MTH({d0})          = leaf_hash(d0)                    # single leaf: the leaf hash itself
MTH(d[0..n]), n>1  = SHA256( 0x01 || MTH(d[0..k]) || MTH(d[k..n]) )
                     where k = largest power of two STRICTLY less than n
```

> **Correction vs. the bead draft.** The draft said "pad by duplicating the last leaf
> hash (RFC 6962-style)." That is **not** RFC 6962 — it is the Bitcoin/older scheme, which
> is vulnerable to CVE-2012-2459 (duplicating the final node lets two distinct trees
> share a root). RFC 6962 **never duplicates leaves**; it instead splits at the largest
> power of two `< n`, giving a left subtree that is a complete binary tree and a
> (recursively defined) right subtree. This handles non-power-of-2 `n` with **no padding
> and no sentinel**, and is the well-vetted Certificate Transparency construction. We
> adopt RFC 6962 exactly; the "duplicate last leaf" and "sentinel hash" alternatives are
> **rejected** (duplication is unsound; a sentinel is unnecessary given the asymmetric
> split).

Empty-batch handling: a batch with zero entries has root `SHA256("")`. The implementation
should refuse to *sign* an empty batch (nothing to attest) but the root function is total.

## 4. Inclusion proof shape

```rust
/// Audit path proving a leaf's membership in a signed root, ordered leaf -> root.
/// Each step is the sibling hash needed to reconstruct the parent at that level,
/// tagged with which side the sibling is on.
pub struct InclusionProof {
    pub leaf_index: u64,
    pub tree_size:  u64,
    pub path: Vec<ProofStep>,   // leaf-to-root order
}
pub struct ProofStep {
    pub direction: SiblingSide, // Left  => sibling is the LEFT child  (parent = H(0x01 || sibling || acc))
                                // Right => sibling is the RIGHT child (parent = H(0x01 || acc || sibling))
    pub hash: [u8; 32],
}
pub enum SiblingSide { Left, Right }
```

Verification (`bd-o4cbn.9.2`):

```text
acc = leaf_hash(entry)
for step in path (leaf -> root):
    acc = match step.direction {
        Left  => SHA256(0x01 || step.hash || acc),
        Right => SHA256(0x01 || acc || step.hash),
    }
assert acc == signed_root
```

`leaf_index` + `tree_size` pin the proof to a specific tree shape so a verifier can
independently re-derive the expected path length and split structure (RFC 6962 §2.1.1
audit path), preventing path-reshaping attacks.

## 5. Root signing preimage

```text
sig_preimage = SHA256( 0x02 || schema_id || batch_id || root_hash || u64_be(timestamp_ns) )
signature    = ed25519_sign(signing_key, sig_preimage)
```

Field widths (all fixed-width, so the concatenation is unambiguous without inner length
prefixes):

| Field          | Width        | Notes |
|----------------|--------------|-------|
| `0x02`         | 1 byte       | **root-signature** domain byte (distinct from `0x00` leaf / `0x01` node) |
| `schema_id`    | 32 bytes     | `SchemaId`/`SchemaHash` of the batch's entry schema |
| `batch_id`     | 16 bytes     | session/batch identifier (e.g. u128 be, or a 16-byte id) — fix the width in `9.2` |
| `root_hash`    | 32 bytes     | the RFC 6962 MTH over the batch |
| `timestamp_ns` | 8 bytes (be) | session signing time, nanoseconds |

The `0x02` byte gives **three disjoint hash domains for free** (`0x00` leaf, `0x01`
internal, `0x02` root signature): no preimage produced in one role can be reinterpreted
in another. Signing `SHA256(preimage)` rather than `preimage` directly keeps the signed
message fixed-width (32 bytes) regardless of `batch_id` width choices.

## Domain-separation summary

| Domain    | Prefix | Hashed structure |
|-----------|--------|------------------|
| Leaf      | `0x00` | `0x00 \|\| u32_be(len) \|\| canonical_bytes(entry)` |
| Internal  | `0x01` | `0x01 \|\| left_hash \|\| right_hash` |
| Root sig  | `0x02` | `0x02 \|\| schema_id \|\| batch_id \|\| root_hash \|\| u64_be(ts_ns)` |

## Acceptance (this bead)

- Design doc exists (this file). ✅
- RFC 6962 cited. ✅ — Laurie, B., Langley, A., Kasper, E., *Certificate Transparency*,
  RFC 6962, IETF, June 2013 (§2.1 Merkle Tree Hash, §2.1.1 Merkle audit paths).
- Deviations recorded. ✅ — see below.

## Deviations from RFC 6962 (recorded per acceptance)

1. **Leaf length prefix (extension, not a conflict).** RFC 6962 defines `leaf_hash =
   HASH(0x00 || d)`. We set `d = u32_be(len) || canonical_bytes(entry)`, i.e. we add the
   project-mandated outer length prefix inside the leaf input. This is strictly a framing
   refinement of `d`; it does not change the tree algorithm.
2. **Root-signature preimage (extension).** RFC 6962 specifies tree hashing but not a
   batch *signing* envelope. The `0x02`-domain `sig_preimage` (§5) is a project addition
   for `SessionSigningBatch`; it reuses RFC 6962's domain-byte discipline (extending the
   `0x00`/`0x01` namespace with `0x02`) to stay collision-safe against leaf/internal
   preimages.
3. **Tree construction: adopted unchanged.** We use RFC 6962's asymmetric power-of-two
   split verbatim and explicitly **reject** the bead draft's "duplicate the last leaf"
   wording (CVE-2012-2459) and the sentinel-padding alternative.
