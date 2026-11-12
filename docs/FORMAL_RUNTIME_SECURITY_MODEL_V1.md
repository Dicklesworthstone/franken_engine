# Formal Runtime Security Model V1

This document is the current mathematical model boundary for FrankenEngine
runtime security. It is deliberately narrower than the long-term theorem-backed
vision: the shipped repository now has explicit finite algebra models and
executable invariant checks, while end-to-end machine-checked proofs for all
security decision algorithms remain hypothesis/target work in the
claim-to-proof matrix.

## Scope

The model covers two enforcement layers used by untrusted extension execution:

- IFC labels and flow authorization in `crates/franken-engine/src/ifc_artifacts.rs`.
- Runtime capability profiles in `crates/franken-engine/src/capability.rs`.

The extracted `crates/franken-core/src/ifc_artifacts.rs` has its own IFC types.
The label-algebra and flow-envelope repairs below apply to both crates; this
is not a claim that their entire policy and receipt APIs are identical.

It does not claim a complete theorem proof for parser correctness, JavaScript
semantic equivalence, probabilistic guardplane optimality, TEE attestation,
transparency-log governance, or proof-carrying optimization.

## IFC Label Algebra

Let `L` be the finite built-in label set:

`Public < Internal < Confidential < Secret < TopSecret`

Custom labels extend the carrier set with an explicit non-negative `u32` level.
Two relations must be distinguished:

- **Sensitivity flow:** `a.can_flow_to(b)` means `a.level() <= b.level()`.
  Distinct labels at the same level can flow to one another. On exact label
  identities this is a preorder, not an antisymmetric order.
- **Exact deterministic order:** `Label::Ord` first compares levels, then puts
  a built-in before a same-level custom label, then orders same-level custom
  labels by name. This is the order used by deterministic collections and by
  label selection in `join` and `meet`.

Both runtime crates select `join(a, b) = max_Ord(a, b)` and
`meet(a, b) = min_Ord(a, b)`. Their sensitivity levels remain respectively
`max(a.level(), b.level())` and `min(a.level(), b.level())`. The same-level
selection rule matters: choosing the left operand on ties makes the exact
computed label, its serialized bytes, and a subsequent exact-label policy
lookup depend on operand order.

Executable obligations:

- Join and meet are idempotent, commutative, associative, and satisfy absorption.
- Join is the least upper bound and meet the greatest lower bound under the
  exact deterministic order; their levels also bound the input sensitivities.
- Computed IR2 labels use `Label::join_all`, so derived data is at least as
  sensitive as every direct input. Empty computed input retains `Public`.
- The focused cross-crate regression suite exercises the built-ins and custom
  labels sharing levels, including `u32::MAX`, plus computed-label serialization
  and exact-policy outcomes. Finite regression coverage is not a theorem over
  arbitrary program execution.

A selected label is not a union of provenance identities. These operations do
not preserve every contributing origin-specific policy prohibition. The repair
removes operand-order dependence; it does not establish full provenance-set
noninterference.

## IFC Flow Policy Semantics

For the **engine** policy `P`, source `s`, and sink `k`,
`FlowPolicy::is_flow_allowed(s, k)` applies this precedence:

1. An exact explicit prohibition returns `Prohibited`.
2. An exact explicit allow returns `Allowed`.
3. An exact declassification route returns `DeclassificationRequired`, even
   when the pair is lattice-legal.
4. Only `FlowPolicyEnforcement::LatticeOpen` admits an otherwise lattice-legal
   pair as `LatticeAllowed`.
5. All remaining flows return `Denied`.

`AllowlistOnly` is the enum default and the serde default for a missing
`enforcement_mode`. `is_flow_allowed_strict` explicitly selects that mode.
Neither lattice legality nor a configured route is permission to bypass an
explicit prohibition. A route identifies a pending obligation, not an executed
declassification.

The **extracted core** policy still has the older interface without an
`enforcement_mode` field and checks lattice legality before declassification
routes. That pre-existing difference is not changed by this repair. Tests of
shared exact-rule behavior construct the engine fixture with explicit
`AllowlistOnly`; they do not assert blanket policy equivalence or weaken the
engine default to match the core.

## Flow-Envelope Sealed-Sink Authorization

`FlowEnvelope::assess_flow_authorization` is a separate authorization boundary
from the policy predicate. It first requires exact source membership in
`producible_labels` and sink membership in `accessible_clearances`.
`envelope_authorized` reports that membership plus the sink's numeric clearance
ceiling; only `flow_authorized` represents immediate permission.

For `SealedSink`, every source whose sensitivity is at least
`Label::Secret.level()` requires declassification, including custom labels.
Matching only the enum variants `Secret | TopSecret` incorrectly admitted a
custom level-3 label without the authorization required for built-in `Secret`.
Both crates now use the numeric level for this decision.

- An in-scope level-3 source without a matching grant remains denied and emits
  `ExplicitAuthorizationRequired`.
- An in-scope higher-level source without a matching grant remains denied and
  emits `DeclassificationObligationRequired`.
- An existing matching built-in grant materializes a concrete obligation;
  immediate permission remains denied until the separate enforcement step.
- A built-in `sealed_sink:secret:...` or `sealed_sink:top_secret:...` grant does
  not authorize a custom label with the same name or level. Custom-label grant
  syntax is not introduced by this repair.
- A grant cannot bypass source or sink membership. Other sink classes retain
  their existing clearance behavior.

The core now reports missing authorization as pending, matching the engine's
assessment interface. Its previous false permission result remains false;
three existing tests retain the denial assertion and now require the exact
blocking advisory instead of claiming no declassification is pending.

## Cryptographic Authenticator (`HMAC`) IFC Ingress-Denial Contract (`bd-vw7s1`)

Cryptographic one-wayness is not information-flow declassification: for a known
message and a low-entropy secret key (such as Node compatibility fixture
`crypto/0015` using `'secret'`), an emitted HMAC tag acts as an offline key
verifier. Furthermore, generic `DeclassificationReceipt` records authorize a
`(source_label, sink_clearance)` obligation pre-execution and do not bind the
computed authenticator bytes at the sink.

Accordingly, `franken_engine` enforces a strict **authenticated-ingress denial
contract** across both static IR2 flow inference (`lowering_pipeline`) and
baseline-interpreter runtime execution (`core_objects_and_descriptors.rs`):

- **Finite ingress clearance (`Internal`):** Both `crypto.createHmac(alg, key)`
  (`builtin:CryptoCreateHmac`) and `hmac.update(data, encoding)`
  (`builtin:CryptoObjectUpdate` when the receiver is an HMAC handle) carry
  effective sink clearance `Label::Internal`. Any input with sensitivity above
  `Internal` (including `Confidential`, `Secret`, `TopSecret`, or same/higher
  numeric custom labels, whether direct, backing-storage-mutated on a `Buffer` /
  `TypedArray` / `DataView`, or tainted via active execution-context / PC flow)
  is denied before an `HmacActive` lifecycle can be created or advanced.
- **No generic receipt bypass:** Runtime HMAC ingress enforcement checks
  `label.can_flow_to(&Label::Internal)` directly and records the audit verdict
  without consulting generic `declassification_receipts`, because extant
  receipts do not bind authenticator output commitments.
- **Defense-in-depth `Secret` preservation:** `Hmac` state and `hmac.digest()`
  continue to join and preserve input/handle/backing-storage labels rather than
  downgrading sensitivity by literal position or digest encoding.
- **Documented compatibility divergence (`crypto/0015`):** Node compatibility
  vector `crypto/0015` (`createHmac('sha256', 'secret').update('msg').digest('hex')`
  flowing to `console.log`) is pinned as an intentional fail-closed product-policy
  divergence rather than weakened via literal demotion or console-clearance
  inflation.
- **Future explicit authenticator-release requirements:** Any future route that
  permits releasing an authenticator derived from `Secret` material must bind
  all six properties at verification time: (1) an explicit authenticator-release
  policy route, (2) cryptographic key-purpose and key-strength/entropy evidence,
  (3) a domain-separated commitment to the exact emitted tag bytes, (4) the
  exact output encoding, (5) the exact trace, call-site, and destination sink
  identities, and (6) sink-time verification with replay-status enforcement.

## Capability Authority Algebra

Let `C` be the finite set of `RuntimeCapability` variants. A
`CapabilityProfile` denotes a subset of `C`.

Subsumption is set inclusion:

`A subsumes B` iff `B.capabilities subset_of A.capabilities`

Attenuation is set intersection:

`attenuate(A, B) = A intersect B`

Executable obligations:

- `FullCaps` subsumes every canonical profile.
- `ComputeOnlyCaps` is the bottom profile and grants no side effects.
- Intersections are commutative, idempotent, and never grant capabilities absent
  from either input.
- Pairwise intersections among `EngineCoreCaps`, `PolicyCaps`, and `RemoteCaps`
  are empty, preserving authority partitioning.
- Deserialization validates canonical profile definitions and rejects profile
  kind/capability smuggling.
- Unknown hostcall tags map to no typed capability and must be rejected by
  callers that require a security capability.

## Implementation Status — Native IFC Repair (2026-09-04)

Committed directly to `main`:

- `069dabee231bb4e5d7b0bae210c01cbff8a59b49`: core exact-label join/meet,
  sensitivity-based sealed-sink admission, pending-authorization results, and
  the initial public-API regressions.
- `0ba18c83a8a2cff7817173a904a6fc2f02efe54c`: initialize the engine-only
  `enforcement_mode` in the shared test fixture, using `AllowlistOnly`.
- `714a83d638ea9b721f67552e1bbada982e8cce28`: engine sealed-sink counterpart
  and the complete 21-instance cross-crate regression source.

Publication review inspected the complete original source and resulting commit
diffs. Native compilation, the new tests, rustfmt, clippy, broader IFC replay,
and independent verification were not executed in the publication environment,
which had no Rust toolchain. Source publication is not a passing verification
result; the commands below remain required. No claim-matrix state, bead closure,
release tag, or package version is promoted by this entry.

Existing label and envelope wire shapes are unchanged. Exact computed core
labels can change for previously order-dependent same-level inputs, and some
core assessment fields intentionally change. Historical trace, hash, and
signature evidence must remain revision-bound rather than being relabeled as
fresh proof under the repaired semantics.

## Verification Commands

Run the native gates in a toolchain-equipped checkout, following the repository's
rch protocol for heavy Cargo work. Focused repair checks:

```bash
cargo test --no-default-features -p frankenengine-engine --test ifc_core_engine_label_semantics -- --nocapture
cargo test --no-default-features -p frankenengine-core --lib ifc_artifacts -- --nocapture
cargo test --no-default-features -p frankenengine-engine --lib ifc_artifacts -- --nocapture
cargo test -p frankenengine-engine --lib ifc_lattice_model -- --nocapture
cargo test -p frankenengine-engine --lib capability_profile_security_algebra -- --nocapture
```

Repository gates remain required, not replaced by the focused tests:

```bash
cargo check --all-targets
cargo clippy --all-targets -- -D warnings
cargo fmt --check
cargo test
```

Proof-smoke bundle with structured logging:

```bash
./scripts/e2e/runtime_security_model_proof_smoke.sh
```

The smoke script writes `manifest.json`, `commands.txt`, `events.jsonl`,
`report.json`, `report.md`, and `redaction_policy.json` using
`franken-engine.proof-artifact-manifest.v1`.

## Claim Boundary

The repository may describe the shipped runtime security layer as
mathematically explicit only when that phrase refers to the finite IFC and
capability algebra above plus the executable invariant checks. Stronger claims,
including theorem-backed security decisions or proof-carrying compilation,
remain governed by `docs/CLAIM_TO_PROOF_MATRIX_V1.md` and must stay
`hypothesis` or `target` until corresponding proof artifacts ship.
