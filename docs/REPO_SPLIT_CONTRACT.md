# Repo Split Contract: franken_engine <-> franken_node

## Objective

Keep engine innovation velocity independent from compatibility-product surface work.

- `/dp/franken_engine`: canonical engine internals and extension-host core.
- `/dp/franken_node`: Node/Bun compatibility surface and product packaging.

## Ownership

`franken_engine` owns:
- Execution semantics, policy semantics, decision/replay primitives.
- Engine crate public APIs and versioning.
- Engine-side benchmarks and core correctness proofs.

`franken_node` owns:
- Product CLI/runtime UX and compatibility entrypoints.
- Compatibility harnesses and migration ergonomics.
- Product distribution and integration tests.

## Dependency Direction

Allowed:
- `franken_node` -> `frankenengine-engine`
- `franken_node` -> `frankenengine-extension-host`
- `franken_engine` -> audited packages from `/dp/franken_native_capsule`

Forbidden:
- `franken_engine` -> `franken_node`
- `franken_native_capsule` -> `franken_engine`
- `franken_native_capsule` -> `franken_node`
- direct production `franken_node` -> `franken_native_capsule` calls
- Copy-paste forks of engine crates inside `franken_node`

## Product-Provisioned Runtime Evidence Authority (`bd-fzpkz`)

The engine owns the evidence authority types and signing semantics; the
downstream product owns production key custody and provisioning. This boundary
does not create a reverse dependency.

| Surface | Owner | Contract |
|---|---|---|
| `RuntimeEvidenceAuthority`, `EvidenceVerificationIdentity`, key provenance, and signature verification | `franken_engine` | Define and validate the typed runtime signing boundary without knowing product persistence paths or product root keys. |
| Production orchestrator construction | `franken_engine` API, invoked by `franken_node` | `ExecutionOrchestrator::try_new_with_runtime_config_and_authority` requires the caller to supply a typed runtime authority. Production construction cannot silently generate or substitute a seed. |
| Persistent product root and per-session seed generation | `franken_node` parent | Keep the long-lived root and durable captures outside the guest project filesystem root, mask that state inside any containment unit that otherwise exposes the host root, generate a fresh short-lived session seed, and bind its complete engine verification identity into a product-root-signed capture. |
| Session execution and result identity | `franken_engine` | Sign runtime evidence with the supplied authority and return the corresponding `EvidenceVerificationIdentity` so the product can reconcile the result against its independently persisted capture. |
| Independent trust | product/operator verifier | Pin the product root outside the capture and use it to authenticate the captured engine identity. An embedded public key alone is not an external trust anchor. |

Deterministic identities remain available only through explicitly lab-scoped
constructors and fixture extension traits. Product code must not import those
paths or use a hard-coded, process-global, producer-known, or child-generated
seed. The product may transmit one short-lived authority into its supervised
execution child, but the persistent product root is never serialized into that
child and its storage path remains outside the guest filesystem provider's
root.

The downstream lifecycle and durable paths are specified by
`/dp/franken_node/docs/ENGINE_SPLIT_CONTRACT.md`. Engine code must not copy that
persistence implementation or depend on the product repository to discover a
key.

## Native-Code Capsule Boundary (`NCC-ENGINE-SPLIT-0010-V1`)

The native-code decision is
[`ADR-0010`](adr/ADR-0010-native-code-capsule-trust-boundary.md), with its
machine-readable state in
[`native_code_capsule_decision_v1.json`](adr/native_code_capsule_decision_v1.json).
It is not implementation authority while that decision says `proposed` and
`implementation_authorized=false`.

If approved:

- `/dp/franken_native_capsule` owns every raw function pointer, executable
  mapping, native relocation, backend adapter, platform mitigation, and
  quiescent unmapping operation.
- That unsafe grant is not repository-wide: the API and worker packages remain
  unsafe-forbidden, and only the runtime package’s exact ADR allowlist of
  architecture raw-invocation and platform executable-memory, unwind,
  process-sandbox, and process-supervisor mechanism modules may contain
  first-party unsafe. Each block needs an invariant ID, local
  proof/test linkage, cfg/feature coverage, and producer-distinct review.
  Build scripts, proc macros, examples, tests, benches, generated source, and
  new unallowlisted modules remain forbidden; transitive unsafe is inventoried
  separately through Cargo metadata, cargo-geiger, and an SBOM.
- `franken_engine` owns JavaScript semantics, lowering to the backend-neutral
  machine-code-free `NativeRegionPlan`, tier policy, separate
  compile/activation authorization policy, deopt/replay semantics, the
  execution-cell protocol, broker policy, and activation/retirement receipt
  consumption. The actual authorization issuer/key service runs outside the
  execution cell, revalidates every untrusted child proposal, and has no
  unsigned or in-cell fallback during signer outage, key rotation, or
  revocation.
- `/dp/franken_native_capsule` consumes the NRP and compile authorization,
  produces/seals the RCO, and owns backend-specific code generation. RCO is a
  compiler output, never an engine-owned compiler input.
- `franken_node` owns product profile UX, packaging, platform deployment
  inputs, supervised engine/cell process lifecycle, and operator recovery. It
  consumes only the public engine boundary and must not call the capsule
  directly.
- FrankenNode owns supervision policy and operations, but any low-level OS
  sandbox/supervisor mechanism that cannot use an audited safe crate lives in
  the capsule allowlist behind a narrow safe engine API. The product still has
  no direct product-to-capsule dependency or call path.
- `franken-native-capsule-worker` is the compiler-isolation process and never
  owns a JavaScript heap or runs untrusted guest code. The distinct
  crash-contained engine-cell worker holds the complete VM/heap/native
  execution state; compiler isolation cannot substitute for it.
- Parent survival and authority confinement are separate claims. The latter
  additionally requires a platform least-authority sandbox and an out-of-cell
  broker holding effects, durable checkpoints, evidence/declassification keys,
  and commit reconciliation. Unknown non-reconcilable effects are typed
  indeterminate and never blindly replayed. A checkpoint emitted after native
  entry by the execution child is an untrusted proposal, not a recovery root.
  Recovery starts from the last pre-native checkpoint bound to the trusted
  broker/evidence prefix, or from state independently reconstructed and
  verified outside the child. The broker does not trust child-supplied IFC
  labels, capability/provenance assertions, evidence, or commit claims. It
  enforces a broker-owned conservative output label derived from all labels
  admitted to the cell and broker-held input lineage. Fine-grained
  language-level IFC keeps the engine/compiler/backend/capsule/generated code
  in its claim-specific TCB; the split does not claim that a broker can infer
  arbitrary value-level dataflow from corrupt child bytes.
  Before native entry, the engine/broker must prove prospective effects accept
  the cell high-water label; otherwise preferred mode uses an independently
  eligible Tier-I transaction and required mode returns a typed explained
  denial. Post-entry escalation may restart in Tier I only from the trusted
  pre-native boundary with broker-proved replay safety; signed declassification
  stays broker-owned.
- `franken_native_capsule` contains no JavaScript semantics and has no
  production dependency on either higher layer.
- Ordinary native profiles do not claim microarchitectural side-channel
  confidentiality. A separately evidenced high-assurance deployment owns core
  isolation/scheduling, SMT policy, cache/NUMA placement, predictor
  mitigations, constant-time key service, cross-tenant red probes, and its
  measured cost.
- Ambient OS core dumps are disabled. Any enabled diagnostic dump is
  broker-written to an encrypted, quota/retention-bounded store, uses no
  guest-controlled filename, treats heap/register/native pages as
  tenant-secret-bearing, and exposes only a redacted operator reference.
- Both existing repositories remain unsafe-forbidden by repository policy;
  shipped source is scanned and production crate targets must compile with
  `unsafe_code` forbidden. Test-only process-environment helpers do not
  authorize native implementation in this workspace.
- The portable package initially wraps Cranelift `0.134.2` from Wasmtime
  `v47.0.2` at `90fed3c6adf53f112c4dea56851728557bb73799` behind
  RCO v1, with exact crate/source/toolchain locks. Copy-and-patch or another
  measured backend may be added behind that same contract without changing
  ownership.
- In-process native execution declares compiler, backend, capsule, ABI, and
  generated code as TCB and makes fatal native faults process-fatal. Parent
  survival is claimed only when the entire execution cell and heap run in a
  child process. Authority confinement additionally names the sandbox, IPC,
  broker, checkpoint, key-service, and supervisor TCB. Compilation-worker
  isolation is not execution isolation.

The production chain remains:

```text
franken_node -> franken_engine -> franken_native_capsule
```

Any reverse edge, direct product-to-capsule runtime call, duplicated native
loader, silent profile fallback, or `unsafe` in either existing repository is
a split-contract violation.

## Release Cadence

- `franken_engine` may release faster than `franken_node`.
- `franken_node` pins engine versions and advances by explicit upgrade PRs.

## CI Matrix (required)

- Pinned matrix: `franken_node` against pinned engine revision.
- Head matrix: `franken_node` against latest `franken_engine` main.

Both must pass before product release.
