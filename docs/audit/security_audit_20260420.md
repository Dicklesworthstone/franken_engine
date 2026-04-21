# FrankenEngine Extension-Host Runtime Security Audit - 2026-04-20

## Scope

This audit adapts the SaaS security-audit kernel to FrankenEngine runtime security. The review focused on capability escape, sandbox bypass, capability escalation, signature-verification bypass, token replay, and RLS-equivalent policy-boundary gaps in these areas:

- `extension_host_authority_guard`
- `capability_witness`
- `capability_token`
- `AuthenticityHash` usage
- `revocation_chain`

The review used the skill operators most relevant to runtime security:

- Surface transpose: compare validation at build, store, publication, verification, and replay surfaces.
- Fail-closed probe: identify APIs whose names imply complete verification but defer mandatory checks to callers.
- Invariant extract: make signed-state assumptions explicit and check which fields are actually enforced.
- Identity-chain trace: follow authority from issuer/signature to active capability or revocation state.

## Findings

### [HIGH] Token frontier identity bindings are signed but not enforced

Bead: `bd-366nq`

`CapabilityToken` signs `CheckpointRef.checkpoint_id` and `RevocationFreshnessRef.revocation_head_hash`, but `VerificationContext` only carries sequence numbers and `verify_token` only compares `verifier_checkpoint_seq` and `verifier_revocation_seq`.

Impact: a verifier on a different checkpoint or revocation-chain fork with an equal or higher sequence can accept a token bound to another trust frontier. This is a token-replay and revocation-freshness bypass across forked or stale state.

Code references:

- `crates/franken-engine/src/capability_token.rs:105`
- `crates/franken-engine/src/capability_token.rs:121`
- `crates/franken-engine/src/capability_token.rs:561`
- `crates/franken-engine/src/capability_token.rs:619`
- `crates/franken-engine/src/capability_token.rs:630`

Required fix: include accepted checkpoint identity and revocation head hash, or an ancestry proof, in verification context and reject mismatches even when sequence numbers are sufficient.

### [HIGH] Capability witnesses can become active without trusted signature verification

Bead: `bd-33yiq`

`WitnessValidator::validate` checks schema, proof coverage, integrity, and confidence, but not synthesizer signatures, promotion signatures, signer trust, or promotion quorum. `WitnessStore::insert` immediately records any witness already marked `Active` as active for its extension. `WitnessIndexStore::index_witness` persists after `verify_integrity` only. `WitnessPublicationPipeline::publish_witness` accepts `Promoted` or `Active` state before appending publication evidence.

Impact: any path that accepts a constructed or restored witness object can treat a forged witness with internally consistent hashes as active or publishable. This is an RLS-equivalent policy-boundary gap for extension capabilities.

Code references:

- `crates/franken-engine/src/capability_witness.rs:1442`
- `crates/franken-engine/src/capability_witness.rs:1522`
- `crates/franken-engine/src/capability_witness.rs:1872`
- `crates/franken-engine/src/capability_witness.rs:2922`
- `crates/franken-engine/src/capability_witness.rs:3062`

Required fix: make active, index, and publish entry points fail closed unless integrity, trusted synthesizer signature, promotion authorization/quorum, and theorem gate all verify.

### [HIGH] Revocation-chain validation omits revocation and head signature checks

Bead: `bd-snh8x`

`RevocationChain::append` accepts a `Revocation` but only checks zone and duplicate target before hashing it into the chain. `verify_chain` walks sequence numbers, previous links, and rolling hashes, but does not verify each revocation signature and does not call `verify_head_signature`; head signature verification is a separate optional API.

Impact: an imported or corrupted chain can pass `verify_chain` with unauthenticated revocation records or an invalid head signature if callers assume chain verification is complete.

Code references:

- `crates/franken-engine/src/revocation_chain.rs:558`
- `crates/franken-engine/src/revocation_chain.rs:697`
- `crates/franken-engine/src/revocation_chain.rs:800`

Required fix: require issuer/key authorization in append/import/verification paths, verify every revocation signature, and make full-chain verification include head-signature validation.

### [MEDIUM] Extension-host authority guard has string-matching bypasses

Bead: `bd-1ggq1`

`extension_host_authority_guard` documents direct upstream-import rejection as the adapter-layer gate, but the default forbidden import list only covers literal `use franken_*` and `extern crate franken_*` prefixes. `check_direct_imports` applies `trimmed.contains` to non-comment lines.

Impact: fully qualified paths, Cargo dependency aliases, re-exports that avoid the literal prefix, and macro-generated access can bypass the CI guard. String matches can also produce false positives in non-code contexts.

Code references:

- `crates/franken-engine/src/extension_host_authority_guard.rs:175`
- `crates/franken-engine/src/extension_host_authority_guard.rs:446`

Required fix: use Rust-aware parsing or resolved metadata, add alias and fully-qualified-path coverage, and document this as CI defense rather than a runtime sandbox boundary.

### [LOW] Keyed authenticity hashes are sometimes compared with `PartialEq`

Bead: `bd-2cyl5`

`AuthenticityHash` provides `constant_time_eq`, but several security-critical HMAC-style `verify_signature` methods compare tags with `==`.

Impact: `PartialEq` has no constant-time contract and can leak tag-prefix matches in high-volume local, co-resident, or high-precision timing settings. This is low-risk compared with the missing authorization checks above, but it is easy to regress and should be made uniform.

Code references:

- `crates/franken-engine/src/hash_tiers.rs:138`
- `crates/franken-engine/src/fleet_convergence.rs:259`
- `crates/franken-engine/src/translation_validation.rs:173`
- `crates/franken-engine/src/translation_validation.rs:224`
- `crates/franken-engine/src/proof_schema.rs:477`
- `crates/franken-engine/src/proof_schema.rs:552`
- `crates/franken-engine/src/translation_validation_receipt.rs:433`

Required fix: replace security-tag comparisons with `constant_time_eq` and add a guard test or lint for `verify_signature` implementations.

## Positive Notes

- Capability-token signatures cover the extended fields, including audience, capabilities, checkpoint references, revocation freshness references, and token ID.
- Publication verification does validate witness synthesis binding and transparency proof signatures when callers explicitly invoke `verify_publication`.
- `AuthenticityHash` itself uses keyed HMAC-SHA256 and exposes a constant-time comparison helper.
- Revocation heads have a dedicated signature verification API; the gap is integration into append/import/full-chain verification.

## Follow-Up Priority

1. Close `bd-33yiq` and `bd-snh8x` first. They affect authority activation and revocation truth.
2. Close `bd-366nq` next. It is the main token-replay/fork-freshness issue.
3. Close `bd-1ggq1` before treating the extension-host guard as a policy gate.
4. Close `bd-2cyl5` as a small crypto-hygiene sweep with regression coverage.
