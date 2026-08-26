# CRYPTO_ASYMMETRIC_KEY_LIFECYCLE_CONTRACT_V1

bd-53l89 phase 1 deliverable. Governs the EC P-256 and Ed25519
`generateKeyPairSync` / `sign` / `verify` surface. Implementation may not land
in slices that violate any section below; each section names the existing
engine mechanism it binds to and the test that must encode it.

Creation gate (AGENTS.md Honest Work):
- **Consumer**: implementers of bd-53l89 follow-up slices; reviewers of any
  diff touching the asymmetric surface or its lowering summaries.
- **Gate**: no lowering recognition, registry row, or interpreter dispatch for
  `generateKeyPairSync`/`createSign`/sign/verify may land unless the sections
  it exercises are implemented and tested. The fail-closed pin
  (`asymmetric_inline_and_escaped_uses_remain_fail_closed`) shrinks only as
  specific forms ship.
- **Observed defect class**: franken_node compat fixtures 0041–0043 red;
  ambient-denial currently masks the entire surface; an ad-hoc implementation
  would bypass the zeroization/IFC precedents the symmetric lane already sets.
- **Deletion condition**: when the surface ships and per-section tests encode
  these properties at HEAD, this document is trimmed to a pointer at the next
  docs pass.

## 1. Authenticated non-forgeable key-object state

Key pairs are engine objects in `InterpreterCore::crypto_objects`
(`baseline_interpreter.rs`, "ObjectId membership ... is the authority"). New
variants:

```text
KeyPairActive { algorithm: Ed25519 | EcP256,
                private_key: Zeroizing<Vec<u8>>,
                public_key: Vec<u8>,          // not secret
                lifecycle_label: Label }
SignActive   { algorithm, private_key ref by ObjectId, input buffer Zeroizing, lifecycle_label }
```

No guest-writable heap property participates in branding or lifecycle
decisions. JS code receives only `Value::Object(ObjectId)` handles. A finalized
or absent ObjectId must yield the typed compatibility error of §5, never a
fallback path. Test: forge attempt via prototype pollution on the handle object
changes nothing (membership check).

## 2. Secure entropy ingress

All key-generation randomness enters exclusively through the audited
RandomRead host effect (`builtin:CryptoRandomBytes` provider path) — the same
typed, journaled channel as `randomBytes`. No direct RNG call anywhere in the
generation path. Consequences:

- Ed25519 seed = exactly 32 provider bytes; P-256 scalar = 32 provider bytes
  rejected-and-redrawn per range check, draws recorded in order.
- ECDSA signing MUST use RFC 6979 deterministic nonces so signing adds **zero**
  entropy draws (replay-stable signatures under fixed inputs).
- Test: two runs over the same scripted provider capture produce identical
  keypairs and identical signatures; witness events show one RandomRead effect
  per generation.

## 3. Private-key zeroization

Private material lives only inside `Zeroizing` storage (§1 fields) and is
wiped on: finalize/drop of the object, `crypto_objects.clear()` on run end,
and replacement during redraw loops. Private bytes are never copied into
guest-visible values, console output, evidence payloads, or error strings.
Test: post-drop memory assertions mirroring `crypto_kdf_zeroized` patterns;
grep-level gate that no `Vec<u8>` private field exists outside `Zeroizing`.

(Revision note: a draft of this section briefly carried a mis-anchored
verify-label edit; the authoritative verify rule lives in §6.)

## 4. Export / receipt / replay policy

v1 posture: **private-key export is denied** with a typed error (§5);
public-key export returns a Public-labeled Buffer. Every generation and sign
effect already lands in the host-effect journal via §2, which is the receipt
layer; replay determinism follows from RFC 6979 plus scripted entropy.
Exporting later requires a new audited capability grant and its own bead — out
of scope here, deliberately.

## 5. Algorithm/key compatibility errors

Typed errors (Node-compatible codes where they exist): unknown curve →
`ERR_INVALID_ARG_VALUE`; wrong-key-type operation (Ed25519 key into ECDSA
sign, P-256 key into Ed25519 verify) → `ERR_INVALID_KEY_TYPE`-class engine
error; operation on finalized/expired ObjectId → the established
finalized-object error family. Errors carry no secret bytes (§3).

## 6. Labels

- Keypair objects take `lifecycle_label` = join of all entropy-derived inputs'
  labels. Under §2 entropy is Secret-sourced
  (`result_contract_for_authority(RandomRead)` = SourceFloor(Secret)), so
  keypair objects are born ≥ Internal only if a future contract says otherwise
  — v1 pins them at the entropy floor actually applied, i.e. **Secret**.
- `sign()` result label = join(lifecycle_label, message label) — a signature is
  derivative of both.
- `verify()` result label = the JoinInputs epilogue join of its operand
  labels (message, signature; the public key is Public). Rationale: a boolean
  verdict over a Secret-labeled message is itself a predicate on secret data,
  so with an all-Public call the verdict is Public and with any Secret
  operand it is at least Secret.
- Lowering summaries mirror these exactly (bd-dign3 pattern); any divergence
  between summary and runtime label is a bug, resolved toward runtime truth.

## 7. Resource budgets

Keypair and sign objects charge `crypto_objects_memory_bytes()` like existing
crypto objects; generation draws and sign operations decrement the instruction
budget through the standard hostcall accounting. No new budget class.

## 8. Rollback/reset behavior

State machine is forward-only: Active → Finalized (per-operation completion)
with no guest-triggered transition back. Failed operations leave the prior
state intact (single atomic state swap on success only). Run teardown clears
all key material (§3). Test: failed verify/sign leaves object reusable;
finalize twice yields §5 errors.

## 9. Product capability grants

Registry rows bind: generation → `builtin:CryptoRandomBytes`-style
**RandomRead** authority (entropy is the grant); sign/verify lifecycle calls →
the existing internal-builtin `JoinInputs` row family with
`supports_lifecycle_capability` extended to the new states. No new
`RuntimeCapability` variant in v1 (avoids perturbing the canonical profile
partition tests); introducing one later is a separate bead with its own
algebra tests.

## Acceptance order

Slices land in this order, each green before the next starts:
1. ed25519 generate (§1,2,3,7,8,9) + ambient-denial pin narrowed to exclude
   only shipped forms;
2. ed25519 sign/verify (§5,6) incl. lowering summaries + Node-vector parity;
3. P-256 generation (§2 redraw rule) then ECDSA sign/verify (§5,6, RFC 6979);
4. fixture parity sweep against `/dp/franken_node` 0041–0043.
