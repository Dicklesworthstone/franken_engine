# ADR-0010: Native-Code Capsule, Trust Boundary, and Repository Split

- Contract marker: `NCC-ADR-0010-V1`
<!-- NCC-APPROVAL-STATE-HEADER-BEGIN -->
- Status: Proposed — explicit project-owner approval is required
<!-- NCC-APPROVAL-STATE-HEADER-END -->
- Date proposed: 2026-07-24
- Owners: FrankenEngine runtime maintainers, native-capsule maintainers, and
  FrankenNode product/runtime operators
- Decision authority: project owner
- Governing bead: `bd-performance-conformance-bridge-tu32j.6.1`
- Plan references: `docs/plans/PLAN_TO_CREATE_FRANKEN_ENGINE.md` §18.2 and
  §18.4
- Machine-readable decision:
  `docs/adr/native_code_capsule_decision_v1.json`
- Project-owner signature trust root:
  `docs/adr/native_code_capsule_owner_trust_root_v1.json`

<!-- NCC-APPROVAL-STATE-NOTICE-BEGIN -->
> [!IMPORTANT]
> This ADR is not accepted yet. It deliberately leaves
> `implementation_authorized=false`. No native backend, executable-memory
> mapper, trampoline, or machine-code invocation may be added on the strength
> of this draft. Acceptance requires an explicit project-owner response
> approving the decision payload identified in the approval record.
<!-- NCC-APPROVAL-STATE-NOTICE-END -->

## Context

FrankenEngine must close as much of the raw-compute gap to Node and Bun as is
technically possible while retaining its de novo execution architecture,
deterministic replay, capability enforcement, IFC, resource accounting, and
evidence guarantees. Tier I can remove substantial interpreter overhead, but
raw-compute parity with mature optimizing engines requires native execution
tiers.

Native execution introduces a boundary that ordinary safe Rust cannot express:

- executable pages must be allocated, populated, protected, cache-flushed,
  entered, retired, and unmapped;
- platform ABIs and native function lifetimes must be obeyed;
- relocation, stack-map, unwind, control-flow, and target-feature metadata must
  agree with the final bytes;
- a compiler bug can emit an arbitrary load, store, stack pivot, or branch;
- a native fault can invalidate the entire process, not merely the current
  JavaScript frame.

The existing repository contract is uncompromising: `franken_engine` and
`franken_node` remain unsafe-forbidden for shipped code, and core execution
cannot become a V8, JavaScriptCore, QuickJS, Boa, or equivalent binding. An
honest native tier therefore needs a separately owned capsule and an explicit
trust statement.

The current production truth is also explicit:

- no executable native backend is linked by `franken-engine`;
- existing Cranelift names describe plans and test fixtures, not machine-code
  execution;
- existing AOT records bind plans and inputs, not executable output bytes;
- the current engine remains the only implemented execution owner.

This ADR changes architecture, not those implementation facts.

## Decision Summary

Subject to explicit approval, FrankenEngine will adopt all of the following as
one indivisible decision:

1. Create a separate sibling repository, `/dp/franken_native_capsule`, whose
   production packages are `frankenengine-native-capsule-api`,
   `frankenengine-native-capsule`, and
   `franken-native-capsule-worker`.
2. Keep every `unsafe` block, raw function pointer, executable-memory mapping,
   platform entitlement adapter, native relocation, and backend-specific
   invocation outside both `franken_engine` and `franken_node`.
3. Select Cranelift as the first portable native backend behind a
   backend-neutral, versioned Region Code Object (RCO) boundary. The
   implementation must pin one mutually compatible Cranelift release set and
   its checksums; the locked 2026-07-24 implementation line is exact
   Cranelift `0.134.2` from Wasmtime `v47.0.2`.

The capsule’s unsafe grant is package/module-scoped, not repository-wide. The
API and worker packages remain `#![forbid(unsafe_code)]`. Only the runtime
package’s exact ADR allowlist of architecture raw-invocation and platform
executable-memory, unwind-registration, process-sandbox, and
process-supervisor mechanism modules may contain first-party unsafe.
Every block needs a stable invariant ID, adjacent safety argument, linked
proof/test evidence, cfg/feature-matrix coverage, and producer-distinct
two-person review. Build scripts, proc macros, examples, tests, benches,
generated source, and newly added unallowlisted modules remain forbidden.
Transitive/vendor unsafe is inventoried separately using Cargo metadata,
cargo-geiger, an SBOM, and explicit risk acceptance.
4. Retain copy-and-patch stencils and whole-interpreter partial evaluation as
   measured Tier-B bakeoff candidates behind the same RCO contract. A custom
   backend is not the initial production default.
5. Record a composable profile tuple on every decision, receipt, and
   measurement: code mode (`tier-i`, `jit`, or `aot`), fault domain, authority
   profile, platform-sandbox profile, and administrator mode (`disabled`,
   `preferred`, or `required`). AOT is a code-delivery mode, not a security
   profile.
6. Publish claim-specific TCBs. Compiler, lowering, runtime/GC, structural
   validator, relocation/linking, platform adapter, capsule, helpers, and
   generated code are the semantic-correctness TCB. Parent survival,
   authority confinement, and exact recovery have different kernel,
   supervisor, IPC, broker, checkpoint, and key-service TCBs. Structural
   validation, provenance signatures, W^X, CFG, CET, PAC, and BTI reduce risk;
   they do not prove arbitrary machine code memory-safe.
7. Make a native fault process-fatal in the process executing the code.
   Catching SIGSEGV, access violation, illegal instruction, stack corruption,
   or equivalent and resuming the same process is forbidden.
8. Use a whole-execution-cell process boundary when a caller requires parent
   survival under arbitrary generated-code corruption. Parent address-space
   survival is not authority confinement: the untrusted-production profile
   additionally requires an out-of-cell effect/key/checkpoint broker and a
   platform least-authority sandbox. Compilation-worker isolation alone
   provides neither execution property.
9. Preserve the one-way production dependency chain:
   `franken_node -> franken_engine -> franken_native_capsule`. The capsule has
   no JavaScript semantics and no production dependency on either higher
   layer.
10. Require distinct ENGINE-issued compile and activation authorizations,
    immutable code identity, prepared/committed/aborted activation records,
    retirement receipts, and broker-proved durable effect/evidence-prefix
    recovery. An unknown, non-reconcilable external-effect commit state is a
    typed indeterminate terminal outcome, never blind replay.

## Alternatives Considered

| Alternative | Strengths | Disqualifying limits | Decision |
| --- | --- | --- | --- |
| AOT only | deterministic build, no runtime compiler, easier signing and deployment review | cannot specialize unknown runtime types/shapes; dynamic code and short-lived workloads fall back; platform-signed code still shares native TCB and fault semantics | retain `aot` as a code mode composed with an explicit fault/authority/sandbox profile, not as a security profile |
| Established backend wrapper | portable x86-64/AArch64 code generation, mature verifier and register allocator, lower implementation risk | backend does not sandbox arbitrary loads/stores; raw pointer and executable-memory lifetime remain unsafe | select Cranelift behind RCO and capsule |
| Copy-and-patch baseline | extremely low compile latency and strong Tier-B hypothesis | architecture-specific stencil inventory, relocation/CFI complexity, proof and maintenance burden | retain in bounded Tier-B bakeoff |
| Whole-interpreter partial evaluation | single-source semantics potential and powerful specialization | compile-time/code-size risk and immature operational evidence for this engine | retain in bounded Tier-B bakeoff |
| New custom optimizing backend | maximum control over hardware-specific decisions | highest wrong-code, ABI, register-allocation, debug, portability, and maintenance risk | reject as initial default; reconsider only after measured non-dominance |
| In-process SFI/independent machine-code validator | potential parent survival without whole-process isolation | must constrain every memory operand, indirect transfer, stack operation, and helper edge; high proof and measured overhead burden | research track only; no current containment claim |
| Borrowed JavaScript engine | mature performance and conformance | violates native-only charter and makes FrankenEngine a binding-led core | forbidden |

The selected backend is a machine-code compiler, not a JavaScript engine.
FrankenEngine lowers bytecode into a backend-neutral, machine-code-free
`NativeRegionPlan` (NRP) that binds the semantics/lowering identity. The
compiler worker consumes NRP plus `CompileAuthorization` and produces/seals the
RCO. The backend owns no language semantics, and the engine never pretends a
post-codegen RCO was its compiler input.

## Portable Package and Dependency Topology

The separate repository is named `/dp/franken_native_capsule`. A local checkout
may live at `/data/projects/franken_native_capsule`, but the logical split
contract uses `/dp`.

It owns three production packages:

| Package | Responsibility | Forbidden responsibility |
| --- | --- | --- |
| `frankenengine-native-capsule-api` | versioned safe request/response types, opaque handles, RCO envelope, authorization envelope, typed exits and receipts | JavaScript values, bytecode semantics, policy choice, tier-routing choice |
| `frankenengine-native-capsule` | backend adapters, relocation, W^X lifecycle, platform CFI/signing integration, raw pointer invocation, quiescent retirement | parser, lowering semantics, hostcall policy, replay policy, product orchestration |
| `franken-native-capsule-worker` | isolated compilation service; bounded IPC; platform self-tests with fixed non-guest probes | owning a JavaScript heap, running code derived from untrusted JavaScript, or silently selecting fallback behavior |

Production dependencies are:

```text
franken_node
    -> franken_engine
        -> franken_native_capsule
            -> pinned Cranelift/backend/platform dependencies
```

Forbidden edges include:

- `franken_native_capsule -> franken_engine`
- `franken_native_capsule -> franken_node`
- `franken_engine -> franken_node`
- direct `franken_node -> franken_native_capsule` runtime calls
- a forked native capsule or engine implementation inside `franken_node`
- executable-memory or raw-invocation code inside either existing repository

Development-only conformance fixtures may consume serialized public contracts,
but they cannot create a production reverse dependency.

There are two different child-process roles, and their names must never be
collapsed:

- the capsule compilation worker contains compiler faults, owns no JavaScript
  heap, and never executes machine code derived from untrusted JavaScript;
- the engine execution-cell worker contains the complete JavaScript VM state,
  heap, native stack, helper table, capsule runtime, generated guest code, and
  every JavaScript agent that shares mutable VM or SharedArrayBuffer state.
  Mutable SharedArrayBuffer state never spans cells. FrankenEngine owns its
  execution protocol; FrankenNode owns launch,
  supervision, kill/reap, and operator recovery. If OS setup cannot be
  expressed through an already-audited safe crate, the capsule’s allowlisted
  platform process-sandbox/supervisor module implements the mechanism behind a
  narrow safe engine-facing API. FrankenNode still calls only the engine
  boundary and never the capsule directly.
- the control-plane authority broker runs outside the cell. FrankenEngine owns
  its policy/capability/IFC/resource semantics; FrankenNode owns deployment and
  operations. It owns durable effect/checkpoint state and key-service calls,
  and treats every cell message as an untrusted proposal.

Running the compiler in the first process does not make native execution
crash-contained. The second process boundary alone permits only the
`native-parent-crash-contained` claim. The `native-crash-contained` claim
additionally requires the complete platform least-authority sandbox,
out-of-cell broker, key/checkpoint custody, and recovery controls to be active
and green.

## Backend Decision

Cranelift is the first portable backend because it supports the required
x86-64 and AArch64 target families, exposes both JIT- and object-oriented
module paths, and has a substantially smaller integration and proof surface
than a new general-purpose backend.

This selection is deliberately bounded:

- the proposed implementation identity is Cranelift `0.134.2`, published from
  Wasmtime `v47.0.2` at
  `90fed3c6adf53f112c4dea56851728557bb73799`, with minimum Rust `1.94.0`;
  the exact crate tarball checksums and upstream `Cargo.lock` digest are in the
  machine-readable decision;
- `bccd12218bb4d16e0f535cd69b4d96994ff3a7ad` is a newer research-head
  architecture snapshot only. It is not the implementation release identity
  and cannot satisfy a release lock;
- the implementation pins an exact, mutually compatible Cranelift crate set,
  source revision, checksums, features, Rust version, license, and SBOM;
- no `cranelift_jit::JITModule`, native pointer, or backend context is exposed
  through the safe engine API;
- Cranelift `JITModule` is not a v1 production emission path: it finalizes into
  its own live executable memory and therefore bypasses the address-free
  sealed-RCO, post-output activation authorization, dormant admission, and
  capsule-owned retirement order. It may be used only for fixed,
  non-production backend research probes until an adapter proves identical
  admission and receipt semantics;
- v1 production uses `cranelift-object` or direct compiled-code/relocation
  extraction into an address-free RCO. The capsule—not the backend module—
  owns reserve, relocate, final-image validation, mapping, activation, and
  retirement;
- the pinned v47 source exposes public finalized-code bytes and relocation/trap
  access through `CompiledCodeBase`/`MachBufferFinalized`, so direct
  address-free extraction is feasible without `JITModule`. That observation is
  not a completeness proof: the bootstrap spike may use only pinned public
  APIs and must prove relocation, trap, unwind, stack-map, and deopt/debug
  metadata completeness for both x86-64 and AArch64 before choosing this path;
- direct codegen and object choices remain internal capsule implementation
  details and must satisfy identical RCO and receipt contracts;
- backend upgrades require the full wrong-code, ABI, relocation, W^X,
  conformance, performance, and rollback matrix before promotion.

Cranelift IR permits fully general loads and stores. The backend verifier
therefore proves well-formed Cranelift IR, not confinement to `VmContext`.
FrankenEngine lowering and capsule validation must enforce the intended access
discipline, but the high-throughput security claim still treats the compiler
and generated code as trusted.

Tier B separately compares:

- copy-and-patch stencils;
- direct Cranelift baseline lowering;
- whole-interpreter partial evaluation.

Selection uses measured compile latency, time to break even, execution time,
code bytes, target coverage, proof burden, failure rate, and operator
diagnostics. The bakeoff may select different backends for different eligible
regions, but every result crosses the same RCO admission and lifecycle
boundary.

## Composable Execution Profiles and User-Visible Eligibility

Every decision, activation record, benchmark sample, crash, and fallback
records the full tuple:

```text
{code_mode, fault_domain, authority_profile, sandbox_profile, operator_mode}
```

`code_mode` is `tier-i`, `jit`, or `aot`. AOT changes compilation time,
packaging, and dynamic-code availability; it does not by itself change the
fault domain or make wrong code safe. The offline compiler, backend,
validator, and generated code remain in the semantic-correctness TCB. AOT may
remove the runtime compiler/backend from the active process while adding
artifact distribution, loading/linking, code-signing, and package verification
to the deployment TCB. Every claim records those TCB changes explicitly.
`operator_mode` is administrator-owned:

- `disabled` never enters native code;
- `preferred` may take a typed pre-entry Tier-I/R fallback;
- `required` fails the operation if the selected native tuple is unavailable.

Guest code and extension manifests cannot select a larger failure domain,
weaker sandbox, or administrator mode.

### `native-throughput`

- `jit` or `aot` code executes in the embedded engine process.
- Generated code is TCB for semantic correctness and shares the engine's
  ambient authority. This profile claims neither parent survival under corrupt
  code nor independent authority confinement.
- A native fault terminates the embedded engine process. No signal/exception
  handler may continue guest execution or claim an in-process Tier-I fallback.
- Eligibility requires a dedicated trust/authority domain, explicit
  administrator selection, a compatible platform adapter, and current
  authorization.
- Raw-compute measurements may use this profile, but must label the complete
  failure/authority tuple and cannot substitute for untrusted production.

### `native-parent-crash-contained`

- The whole execution cell—VM state, heap, native stack, helper table, capsule,
  generated code, and the complete SharedArrayBuffer/Atomics agent cluster—
  runs in a long-lived child process. Cross-cell mutable SharedArrayBuffer
  state is forbidden.
- Kernel process isolation, authenticated/bounded IPC, descriptor/handle
  discipline, no shared mutable VM memory, descendant containment, and the
  supervisor are TCB for the parent-survival claim.
- This profile protects the parent address space and lifecycle only. It does
  not by itself stop arbitrary syscalls, same-user filesystem access, inherited
  handles, signing-key theft, or capability/IFC/evidence bypass inside the
  child. It is limited to fuzzing, bring-up, and explicitly labeled
  non-authority-contained deployments.

### `native-crash-contained`

- This is the default native posture for untrusted production extensions only
  when every parent-survival and authority-confinement control is green.
- It includes the whole-cell child boundary above plus a platform
  least-authority sandbox and an out-of-cell, policy-enforcing effect broker.
- The child has no ambient filesystem, network, device, process-launch, or
  long-lived signing/declassification-key authority. The broker revalidates
  tenant/cell identity, coarse capability ceilings, policy, budgets, epochs,
  sequence, and idempotency; child assertions are untrusted proposals.
- A memory-corrupted cell can forge a value label just as it can forge any
  other child byte. The broker therefore ignores child-supplied public labels
  and enforces an independently maintained conservative output label: the join
  of all labels admitted to the cell plus broker-derived input lineage.
  Fine-grained language-level capability/IFC semantics still include the
  engine, compiler, backend, capsule, helpers, and generated code in their
  claim-specific TCB. We do not claim arbitrary-code-resilient fine IFC.
  A future stronger profile would need unforgeable broker-owned labeled
  handles or equivalent externally derivable provenance, with separate proof
  and performance evidence.
- Conservative labeling must not silently change JavaScript behavior. Before
  native entry, eligibility proves every prospective effect accepts the
  broker-owned cell high-water label; otherwise `preferred` routes the whole
  transaction to an independently eligible Tier-I path and `required` returns
  a typed policy denial with `doctor`/`explain` evidence. If the label escalates
  after entry, the broker denies the unapproved effect and may restart from the
  trusted pre-native boundary in Tier I only when its own effect journal proves
  replay safe; otherwise the result is typed partial/indeterminate. Signed
  declassification remains broker-owned. Mixed-label overtaint denial and
  fallback rates are measured as user-visible costs.
- Durable effect journals, checkpoints, evidence signing, and long-lived keys
  stay outside the child. One child contains one declared authority/tenant
  domain.
- The parent sends work at cell or transaction boundaries; it does not perform
  per-opcode or per-property IPC.
- The performance claim includes process startup/reuse, IPC, sandbox, broker,
  checkpoint, recovery, and supervision costs and compares Node/Bun under
  equivalent behavior.

### `portable-tier-i`

- No native code is mapped or entered.
- This is the universal portable path for denied entitlements, unsupported
  platforms/features, failed validation, exhausted code budgets, missing
  capsule, invalid signatures, stale epochs, or administrator disablement.
- It preserves Tier-I/R semantics and security but makes no native-performance
  claim.

Silent movement along any tuple axis is forbidden. A pre-entry refusal follows
the administrator mode and may use only an independently eligible configured
code mode or Tier I/R. A post-entry fatal native fault requires process
termination and, where applicable, supervisor recovery; it cannot be relabeled
as an ordinary deoptimization.

## Compilation Isolation Is Not Execution Isolation

Compilation runs off the execution thread and should normally run in the
least-authority `franken-native-capsule-worker`. That worker receives an
immutable engine-owned NRP, compile authorization, target/profile metadata,
and only the runtime facts explicitly authorized by a compilation transcript.
It emits the sealed RCO; an RCO is never described as its own input. The worker
must not receive ambient
filesystem/network access or unrelated tenant secrets, and it never becomes
the engine execution-cell worker merely because it can load the capsule for
fixed platform self-tests.

This protects the caller from bugs or compromise in compiler implementation.
It does not make the bytes safe after they enter the execution process.

The execution containment statement is determined solely by where the final
machine code runs:

- in-process execution means the current process is the failure domain;
- child-cell execution means the child process is the failure domain;
- future SFI or an independently proved validator may narrow that domain only
  after executable evidence and a new ADR revision.

## Region Code Object Contract

The Region Code Object is the only backend-to-capsule admission format. RCO
schema v1 is immutable and target-specific. It contains no live process
addresses.

Every RCO binds:

- RCO schema and capsule ABI versions;
- source, AST, IR, bytecode-semantics, compiler, backend, generator, and
  transcript hashes;
- target triple, pointer width, endianness, ISA baseline, optional feature
  mask, and platform ABI;
- code and read-only-data bytes or sealed sections;
- allowlisted relocation records whose targets are RCO-local symbols or typed
  helper IDs, never arbitrary host addresses;
- entrypoint offsets and signature IDs;
- code bounds and valid direct/indirect branch targets;
- safepoints, strong/weak stack maps, deopt maps, materialization reservations,
  exception/status maps, and OSR entry/exit maps;
- floating-point control-state save/restore, spec-exact NaN/negative-zero
  behavior, forbidden nondeterministic or direct-syscall instructions, and the
  rule that Rust/platform unwinding never crosses the native ABI;
- the validator rejects or explicitly guards direct syscall/trap gateways,
  `RDTSC`/`RDTSCP`, `RDRAND`/`RDSEED`, privileged state changes, unauthorized
  TLS/signal-state access, and any architecture-specific nondeterminism.
  Target support such as x86-64-v3 does not by itself authorize FMA
  contraction, FTZ/DAZ changes, x87/MXCSR/FPCR drift, or observable changes to
  NaN and signed-zero behavior;
- budget, interrupt, capability, IFC, policy, and evidence checkpoints;
- assumptions, watchpoints, security/policy/proof epochs, and invalidation
  domains;
- compile CPU, transient memory, executable bytes, metadata bytes, and
  activation resource estimates;
- debug/source/perf-map identities and redaction classification;
- compiler provenance, signature envelope, source locks, SBOM, and license
  decision.

The pipeline is:

```text
lower to NRP -> ENGINE compile-authorize -> compile -> seal RCO
      -> compile receipt
      -> ENGINE activation-authorize -> structural validate
      -> reserve -> relocate -> validate final image -> flush instruction cache
      -> enforce RX -> register CFI/unwind metadata -> prepare
      -> install dormant route -> commit admission -> enable entry atomically
      -> record entry enabled -> execute -> unroute -> quiesce
      -> unregister -> confidential zero -> unmap -> retire
```

“Structural validate” means schema, bounds, relocation, entrypoint, metadata,
target, authorization, and internal-consistency checks. It does not mean that
arbitrary machine instructions have been independently proved memory-safe.

## ENGINE Compile and Activation Authorization

The capsule is a mechanism, not a policy engine. Authorization is deliberately
two-phase so it never claims to bind an output hash before the output exists.

Before compilation, engine-owned policy logic running in the out-of-cell
control-plane native-authorization service revalidates an untrusted request
and issues a single-use or bounded-replay `CompileAuthorization`. The
execution-cell engine can submit only an unsigned proposal; it cannot hold the
issuer key, mint an authorization, or treat its own policy/epoch assertions as
authoritative. The authorization binds:

- source, semantic-IR, and lowering hashes;
- tenant, extension, package, realm, execution-cell, and authority-domain IDs;
- the complete execution-profile tuple;
- compiler/backend/capsule identities;
- target, feature mask, capsule ABI, and RCO schema;
- capability, IFC, policy, proof, revocation, and security epochs;
- compile CPU, transient-memory, output-byte, and variant budgets;
- not-before, expiry, nonce, attempt, and replay rules;
- engine signature and decision/evidence linkage.

The compiler emits a `CompileReceipt` binding that authorization, the actual
transcript, and the sealed RCO hash. Only after the sealed RCO exists may the
same out-of-cell service independently revalidate the result and issue an
`ActivationAuthorization`. It binds the compile authorization and receipt,
sealed RCO and final pre-relocation hashes, exact helper IDs,
target/ABI/features, code-memory and runtime budgets, policy/security epochs,
and the supervisor/broker/sandbox/recovery contract.

Unknown fields, unknown helpers, stale epochs, target mismatch, duplicate
nonces, expired authorization, over-budget estimates, an unavailable or stale
signer, or a noncanonical signature fail before the relevant phase. Key
rotation and revocation force epoch revalidation and reject the old key; there
is no unsigned or in-cell fallback. A compile authorization can never activate
code, and an activation authorization cannot authorize a different compile
transcript or RCO.

Authorization and signatures prove provenance and policy approval. They do not
turn corrupt bytes into safe bytes.

The same boundary applies to confidentiality claims: the sandbox and broker
can confine ambient authority and enforce a conservative cell-wide label, but
they cannot reconstruct arbitrary value-level dataflow from bytes emitted by
corrupt native code.

## Executable-Memory and Platform Contract

Common rules:

- no physical page may have a live writable alias while it is executable;
- initial mapping is non-executable and writable only for bounded population;
- relocation targets and all metadata are revalidated against the populated
  image;
- instruction/data caches are synchronized as required by the ISA and OS;
- write authority is revoked before dormant-handle installation;
- executable entrypoints become callable only after CFI/platform registration
  and a durable prepared activation record; dormant installation is not
  guest-routable, committed admission is durable before entry enable, and the
  atomic entry-enable step is the callable linearization point;
- patching creates a new inactive image and epoch-swaps it; executing pages are
  never edited in place;
- retirement unroutes first, waits for quiescence, unregisters metadata,
  zeros confidential material before unmapping, refunds budget, and emits a
  receipt;
- guard pages and code/data separation are required where the platform
  supports them;
- unsupported or denied platform controls produce a typed fallback, never a
  silent weaker mode.

### Linux owner

`franken_native_capsule::platform::linux` owns Linux x86-64 and AArch64
mapping, protection, cache synchronization, process sandbox, crash, and
retirement behavior.

- Use dedicated page-aligned mappings, populate as `RW`, and transition to
  `RX` with `mprotect`; do not allocate from a general heap.
- A transferred `memfd` must be sealed before another process maps it, and all
  writable mappings must be gone before executable mapping.
- The authority-contained worker uses no-new-privileges plus the supported
  namespace, Landlock, seccomp, cgroup, descriptor/channel-allowlist, and
  broker controls. Missing required controls are typed unavailable rather than
  silently weakened.
- An independent parent watchdog enforces hard wall/CPU/RSS/process/descendant
  limits even if native code stops polling, then kills/reaps the process group.
- Feature-detect kernel/ISA controls and record unavailable controls rather
  than substituting them.

### Apple owner

`franken_native_capsule::platform::apple` owns macOS Apple Silicon and
x86-64 mapping, entitlements, callback allowlist, cache synchronization,
pointer signing, crash, and retirement behavior.

- Hardened-runtime JIT requires the appropriate `allow-jit` entitlement and
  `MAP_JIT`.
- On supported macOS versions, use the JIT write-callback allowlist path and
  freeze the allowlist before untrusted input. Do not mix it with an
  incompatible write-protection API.
- Respect the platform's one-`MAP_JIT`-region constraint by managing bounded
  subregions and epoch-safe reuse.
- Call the required instruction-cache invalidation before entry.
- PAC/arm64e and branch-target controls are enabled when the target, backend,
  signing identity, and deployment profile support them. Lack of support is an
  explicit matrix result.
- Missing entitlement, callback authorization, notarization, signing, or
  target support produces a typed pre-entry refusal and follows the explicit
  administrator mode; it does not silently switch to AOT or Tier I.
- Authority confinement additionally requires a sandboxed service/process
  profile, descriptor/channel allowlist, bounded resources, independent
  watchdog, broker-only external effects, and no in-cell long-lived
  signing/declassification keys. If that boundary is unavailable, the
  authority-contained tuple is unavailable even when `MAP_JIT` works.
- Because JIT write authorization is thread-scoped within the platform's
  `MAP_JIT` region, population/reuse must prove the writable callback can touch
  only an inactive bounded subregion and cannot modify any routable region.

### Windows owner

`franken_native_capsule::platform::windows` owns Windows x64 first, with
Windows AArch64 represented explicitly as supported or typed-unavailable.

- Use dedicated `VirtualAlloc` regions, populate non-executable memory,
  transition with `VirtualProtect`, and call `FlushInstructionCache`.
- When CFG is enabled, allocate executable regions as invalid indirect-call
  targets and register only exact validated entries with
  `SetProcessValidCallTargets`; the platform default that treats executable
  pages as valid targets is insufficient.
- Register and unregister required dynamic function/unwind tables before
  activation and after quiescence.
- Record CFG, CET, target-feature, job-object, crash, and process-mitigation
  state in the activation receipt.
- Authority confinement additionally requires a restricted-token or
  AppContainer support matrix, inherited handle/channel allowlist, independent
  watchdog, broker-only external effects, and no in-cell long-lived signing or
  declassification keys.
- Unsupported mitigation or registration states produce a typed refusal and
  follow the administrator mode or an explicitly selected weaker
  non-production tuple.

CFI, CET, PAC, and BTI are defense-in-depth. They constrain classes of control
transfer but are not a substitute for memory isolation or compiler trust.

## Microarchitectural Side-Channel Scope

Process, sandbox, broker, CFI, and W^X controls do not by themselves contain
cache, branch-predictor, SMT-sibling, memory-controller, or NUMA/co-residency
leakage. The ordinary native profiles make no microarchitectural side-channel
confidentiality claim.

A separately named high-assurance deployment profile may make a narrower
claim only with tenant core isolation or core scheduling, an explicit SMT
disable/trusted-sibling policy, cache/NUMA/memory-placement controls,
architecture-specific predictor/serialization mitigations, a constant-time
out-of-cell key service, cross-tenant Prime+Probe/branch-target-style red
probes, and published throughput/latency/capacity cost. Missing executor or
red-team evidence excludes the claim; process isolation never implies it.

## Cache, Activation, and Retirement

The durable cache stores immutable RCOs and AOT images, not live executable
pointers. Immutable artifact identity includes semantics, compiler, backend,
code mode, target, ABI, applicable epochs, and RCO content. Per-attempt
activation authorization, nonce, and expiry are a separate binding and never
poison content-addressed reuse.

Artifacts are classified public-shareable, tenant-scoped, or
tenant-secret-bearing. Source, specialized constants, PGO facts, code/rodata,
debug/perf data, and crash dumps inherit that classification.
Tenant-secret-bearing artifacts are tenant-bound, encrypted at rest, retained
for a bounded interval, redacted in diagnostics, zeroed before release, and
never deduplicated across tenants.

Ambient OS core dumps are disabled by default. If an operator explicitly
enables diagnostic dumps, the supervisor writes them only through a
broker-controlled encrypted, quota-bounded, retention-bounded store; the guest
and extension never choose a filename. Full heap, register, native stack/code,
and mapped-page content is tenant-secret-bearing. Quota exhaustion or key
service failure denies the dump while preserving a typed terminal-fault
record. Operator output contains only a redacted reference and policy outcome,
and expiry or verified zero is mandatory.

Activation is transactional:

1. authenticate and parse the immutable RCO;
2. verify current authorization and reserve all resources;
3. create an inactive writable image;
4. apply only allowlisted relocations;
5. hash final code/rodata/metadata and validate all offsets;
6. synchronize instruction cache and revoke write access;
7. register CFI, unwind, debug, and profiler metadata;
8. emit a durable signed `prepared` record that makes no routability claim;
9. install an opaque dormant `CodeHandle` that cannot be entered;
10. emit a linked signed `admission-committed` record. It authorizes the
    enable step but does not claim guest routability;
11. atomically enable entry. This is the activation linearization point;
12. emit a linked signed `entry-enabled` observation record.

Any pre-enable failure emits or is reconciled to `aborted`, unregisters all
partial metadata, unmaps/zeros the inactive image, and refunds its reservation.
A crash after `admission-committed` but before enable cannot execute code;
process death removes the dormant route and recovery links an
aborted/lost-process record. A crash after the enable linearization point but
before the observation record is an explicit
`activation-outcome-indeterminate` reconciliation case; an admission record
must never be relabeled as proof that entry occurred. Broker/evidence records,
not child assertions, determine any externally visible prefix. The prior
active image remains valid during an ordinary failed replacement.

Retirement is also transactional:

1. remove the handle from new routing;
2. advance the execution epoch;
3. wait until no stack, OSR map, deopt map, callback, or profiler reader can
   reference the image;
4. unregister metadata;
5. zero confidential code, rodata, PGO, debug, and other metadata as required;
6. unmap;
7. refund quotas;
8. emit a signed retirement receipt that links the committed activation
   receipt.

Cache eviction never implies immediate executable unmapping. Unknown liveness,
timeout, metadata mismatch, or failed unregister keeps the object quarantined
and blocks reuse.

## Fault, Recovery, and Fallback Semantics

Before native entry, any failure can return a typed refusal and route to Tier
I/R with no guest-visible partial effect.

After native entry:

- ordinary guard failure, invalidation, interrupt, budget exhaustion, and
  declared exception may use a tested safepoint/deopt/status ABI;
- an independent parent watchdog enforces hard hangs and resource ceilings
  even when corrupt native code ignores every safepoint;
- SIGSEGV, SIGBUS, SIGILL, stack corruption, CFG violation, access violation,
  PAC/BTI/CET failure, or equivalent is process-fatal;
- no handler may convert a fatal native fault into an in-process JavaScript
  exception or resume at Tier I;
- the supervisor records the crash identity and last durable prefix, kills and
  reaps the entire process group, and starts a fresh process;
- durable checkpoints, effect journals, policy state, evidence signing, and
  long-lived signing/declassification keys live outside the child;
- native entry creates a last-trusted-boundary record over a pre-entry
  checkpoint and its broker/evidence prefix. A checkpoint produced by a child
  after it entered potentially corrupt native code is an untrusted proposal,
  not a recovery root;
- a later checkpoint is eligible only if a trusted component outside the
  execution child independently reconstructs or verifies all state needed for
  the claimed recovery class. Otherwise recovery restarts from the pre-native
  checkpoint and replays broker-held nondeterminism and effect receipts;
- a fault during active shared-memory concurrency is recoverable only from a
  proven quiescent agent-cluster checkpoint. Otherwise the cluster terminates
  with a typed non-replayable outcome; the system must not claim deterministic
  replay of an unobserved Atomics interleaving;
- every external effect crosses the out-of-cell broker, which durably reserves
  sequence/idempotency state before dispatch and records a commit or
  reconciliation receipt;
- external effects include stdout/stderr, streamed response bytes, and
  product-visible return delivery—not only hostcalls. Bounded output is
  buffered until commit; otherwise it is brokered with sequence/idempotency
  metadata, or a crash after partial delivery ends in a typed
  partial/indeterminate outcome with no automatic retry;
- recovery resumes only from an eligible checkpoint whose host effects,
  nondeterminism, policy epochs, and evidence form an exact hash-linked prefix
  proven by trusted components outside the child;
- child-supplied IFC labels, capability claims, provenance, evidence, or
  commit assertions are never authoritative. The broker rederives or verifies
  sufficient provenance from trusted policy state, authenticated input
  lineage, and its own journal before authorizing an effect;
- if an in-flight effect can be proved committed or not committed, recovery
  consumes that proof. If the provider cannot establish either state, the run
  ends with typed `indeterminate-external-effect` quarantine and requires
  operator/provider reconciliation; it is never automatically replayed;
- the “never duplicated or omitted” claim applies only to effect classes with
  broker proof of commit state. Other classes make the explicit indeterminate
  guarantee above.

Native eligibility also consults a versioned recovery-class registry owned by
FrankenEngine. It classifies live sockets/files/process handles, timers and
job queues, pending promises, generators/async suspension, WeakRef/finalizer
state, module evaluation, SharedArrayBuffer/Atomics clusters, pending output,
and product-visible return delivery. Each class has an owner, reason, and one
of three explicit dispositions: trusted quiescent checkpoint plus broker
replay, pre-entry Tier-I fallback, or typed terminal
non-replayable/indeterminate outcome after a fatal fault. An unknown live-state
class fails closed before native entry. No profile may “recover” by silently
dropping a JavaScript or product feature.

The exact recovery algorithm is implemented and proved by later BRIDGE-05,
host-effect, replay, and BRIDGE-21 beads. This ADR freezes the failure contract;
it does not claim that recovery is implemented today.

## Supply Chain, Licensing, and Signing

Before any backend or capsule release:

- pin exact dependency versions, source commits, checksums, enabled features,
  Rust toolchain, target SDK, linker, and platform headers;
- generate and retain an SBOM and provenance statement for every platform
  binary;
- record license expressions and notices. The evaluated Cranelift/Wasmtime
  source uses `Apache-2.0 WITH LLVM-exception`;
- scan source and binary dependencies, but never treat a clean scanner result
  as a correctness proof;
- require two-person review for unsafe boundary, relocation, W^X, CFI, raw
  invocation, and retirement changes;
- sign capsule packages separately from RCO compiler output and separately
  from activation/retirement receipts;
- keep authorization, evidence, declassification, checkpoint, effect-commit,
  and durable receipt private keys outside the execution cell. A child can
  submit an untrusted proposal but cannot mint the proof used to recover or
  expand authority;
- bind platform entitlements, code-signing identity, notarization, Windows
  signing, Linux package provenance, backend build, and capsule ABI into a
  platform-signing envelope;
- support revocation and rollback to the previous compatible capsule/backend
  without invalidating portable Tier I/R.

Compiler signatures establish origin. The capsule must still validate the
current bytes and authorization.

## Claims and Measurement

The following claims remain separate, and each records the complete
`{code_mode, fault_domain, authority_profile, sandbox_profile, operator_mode}`
tuple:

| Claim | Required denominator |
| --- | --- |
| raw-compute closeness | `native-throughput`, including embedded process-fatal semantics |
| parent-survival throughput | `native-parent-crash-contained`, explicitly making no authority-confinement claim |
| untrusted production throughput | `native-crash-contained`, including sandbox, broker, worker lifecycle, IPC, checkpoint, and supervision |
| AOT startup/steady state | `code_mode=aot` composed with a named fault/authority/sandbox profile, including build, signature, install, target selection, and fallback |
| portable semantics | `portable-tier-i`, with no native-performance implication |

No result may:

- quote a throughput profile as crash-contained;
- omit compilation, activation, code memory, process, or recovery costs from
  the profile that owns them;
- count a silent Tier-I fallback as native execution;
- treat a generated input hash as an executable-output hash;
- compare against Node/Bun without equivalent isolation, policy, security, and
  evidence behavior;
- publish a native security claim from W^X/CFI/signature evidence alone.

Every native measurement records actual tier entry, executable hash, all five
profile axes, claim-specific TCB, target features, backend/capsule versions,
entitlements, mitigations, fallback eligibility, and all attempts.

## Ownership and Review

| Surface | Accountable owner | Required reviewers |
| --- | --- | --- |
| JavaScript semantics, IR/RCO lowering, tier policy, ENGINE authorization | `franken_engine` | semantics, security, replay |
| capsule API/RCO wire, backend adapters, unsafe boundary, mapping, invocation, retirement | `franken_native_capsule` | unsafe/memory, compiler, platform |
| Linux x86-64/AArch64 adapter | capsule Linux owner | security + both ISA owners |
| Apple arm64/x86-64 adapter and entitlements | capsule Apple owner | Apple platform/signing + AArch64 |
| Windows x64/AArch64 support matrix | capsule Windows owner | Windows platform/security |
| execution-cell sandbox, IPC peer authentication, hard watchdog and descendant containment | engine + product platform owners | security, SRE, platform |
| out-of-cell authority/effect broker, durable checkpoint/effect journal and commit-unknown semantics | engine host-effect + product recovery owners | security, replay, storage, SRE |
| authorization/evidence/declassification/receipt key custody | control-plane key owner outside the cell | cryptography + security + SRE |
| product profile UX, packaging, engine-worker supervision, recovery operations | `franken_node` | product, SRE, security |
| independent activation/retirement/claim verification | BRIDGE-21 verifier owner | producer-distinct reviewer |
| architecture acceptance | project owner | explicit approval required |

An owner may be a named team until individual maintainers are assigned. An
unowned platform, key, mitigation, or recovery step is unsupported and fails
closed.

## Rollout, Fallback, and Kill Rules

1. No implementation starts before this ADR is accepted.
2. RCO/ABI schema and the red-first BRIDGE-05 harness land before backend
   activation.
3. Bring-up starts in `native-parent-crash-contained`, non-production cells
   with Tier I/R as the oracle; it cannot be labeled authority-contained.
4. Each platform independently proves map/populate/protect/flush/register/
   enter/quiesce/unregister/unmap behavior.
5. Native execution remains administrator-`disabled` until wrong-code,
   fatal-fault, sandbox, broker, key custody, scoped exact-prefix recovery,
   resource, conformance, and performance gates are green. Promotion proceeds
   to `preferred`; `required` is a separate operator decision.
6. A backend/platform/profile is killed or rolled back on unexplained wrong
   code, inability to preserve exact effects, ambiguous native entry, W^X
   violation, stale authorization acceptance, unbounded compiler resource use,
   unowned mitigation, or failure to beat its measured crossover.
7. Removing a native profile never removes Tier I/R, replay, or conformance
   capability.

## Verification Contract

This decision is checked by:

- `scripts/run_native_code_capsule_adr_gate.sh`
- `scripts/e2e/native_code_capsule_adr_contract_smoke.sh`

The ADR gate validates the machine-readable decision, this ADR, the
authoritative plan, and both repository split contracts. It distinguishes a
valid proposed decision from an authorized accepted decision.

Self-tests and the public E2E must cover:

- valid proposed and valid accepted states;
- malformed, missing, duplicate, reordered, stale, and tampered decision
  inputs;
- an unsafe implementation placed in either existing repository;
- ambiguous or missing TCB;
- a signature incorrectly described as memory safety;
- fake catch-and-fallback after a native fault;
- compilation-worker isolation mislabeled as execution isolation;
- forged, missing, stale, or payload-mismatched approval;
- reversed or direct product-to-capsule dependency;
- stale engine or product split contract;
- missing Linux, Apple, or Windows owner;
- missing RCO, authorization, activation, retirement, signing, or source-lock
  domain.
- SharedArrayBuffer/Atomics agent-cluster containment, quiescent-checkpoint
  recovery, and typed refusal of unprovable concurrent replay.

The gate emits bounded versioned JSONL and retains a reproducibility bundle with
run/trace/test/scenario/seed/attempt/source-cutoff/platform/phase/sequence/
decision/reason/duration/artifact hashes, commands, environment, source locks,
review state, provenance graph, `repro.lock`, and `LEGAL.md`.

BRIDGE-21-R11 later owns the red-first executable native-capsule harness. This
ADR gate certifies the architecture contract only; it cannot publish a passing
native-runtime verdict.

## Research and Normative Source Lock

The machine-readable decision contains the complete source-lock list and a
`source_claims` map from each architectural conclusion to its source IDs and
clause/code locators. Each conclusion remains an architecture input, platform
input, supply-chain input, or research hypothesis—not runtime evidence. The
important conclusions are:

- Cranelift has general loads/stores and a `vmctx`; this supports VM codegen
  but is not an arbitrary-code sandbox.
- Cranelift JIT modules expose raw finalized addresses and unsafe retirement,
  so those lifetimes stay inside the capsule.
- Apple Silicon requires platform-specific JIT entitlements, write
  authorization, and instruction-cache invalidation.
- Windows executable pages need explicit protection/cache handling, and CFG
  defaults must be narrowed to exact JIT entrypoints.
- Linux page protections fault the process on invalid access; process
  isolation, not a signal-based continuation trick, defines containment.
- copy-and-patch and newer baseline meta-compilation research justify a
  measured Tier-B bakeoff, not an implementation claim;
- whole-program interpreter partial evaluation, Deegen-style generated
  interpreter/baseline-JIT machinery, two-tier meta-tracing, and the VMIL 2025
  Copy-and-Patch R case study are separate upstream methods to reproduce and
  compare. Their reported results are research inputs, never FrankenEngine
  runtime evidence, and no one may turn them into an untracked second
  semantics implementation.

Source hashes were captured on 2026-07-24. Upstream drift requires an explicit
source-lock refresh and review; it cannot silently change this decision.
Mutable documentation endpoints are content-addressed by the recorded digest;
the retrieval date alone is not treated as an immutable identity. An
accepted-state closure run retrieves every allowlisted source and crate
archive in explicit online-verification mode, rejects redirects outside the
declared HTTPS origin, checks its byte digest, and retains the exact bytes plus
retrieval receipt in the immutable candidate bundle. Later offline
reproduction verifies those retained bytes; it does not substitute a mutable
network response. A proposed-state local run may be offline, but must label
source verification `not-performed` and cannot be used for implementation
authorization.

## Consequences

Positive:

- FrankenEngine gains a credible path to raw-compute performance without
  weakening the no-binding or no-unsafe-in-repository rules.
- The unsafe and platform-specific surface becomes small, named, auditable,
  independently fuzzable, and replaceable.
- Native fault semantics are honest and operationally recoverable.
- High-throughput, parent-survival, and authority-contained measurements cannot
  be conflated, and AOT cannot be presented as a security profile.
- Backend innovation remains possible behind a stable RCO boundary.
- `franken_node` stays a product/compatibility layer rather than acquiring a
  second engine implementation.

Costs:

- A third repository and platform-specific release train must be maintained.
- The compiler/capsule/generated-code TCB is substantial until an independent
  validator or SFI proof exists.
- Authority-contained execution adds sandbox, broker, process, checkpoint, key
  service, and supervision cost.
- Five explicit profile axes increase testing and operator UX complexity.
- Native release requires hardware/platform labs, signing identities, and
  producer-distinct review.

## Non-Goals

This ADR does not:

- claim that any native backend or executable capsule is implemented;
- approve `unsafe` inside `franken_engine` or `franken_node`;
- approve a borrowed JavaScript engine;
- freeze the detailed VM ABI owned by BRIDGE-05.2;
- preselect the Tier-B bakeoff winner;
- claim Cranelift, a signature, W^X, CFG, CET, PAC, or BTI is a memory sandbox;
- authorize publishing, platform signing, entitlements, or external release;
- permit recovery in a process after a fatal native fault;
- replace later conformance, fuzz, performance, or independent verification.

## Approval Record

Current state:

<!-- NCC-APPROVAL-STATE-RECORD-BEGIN -->
- decision state: `proposed`
- implementation authorized: `false`
- approved payload digest: absent
- approval authority: project owner
- approval text: absent
<!-- NCC-APPROVAL-STATE-RECORD-END -->

Acceptance procedure:

1. while the decision remains `proposed`, identify and enroll the project
   owner's Ed25519 public key through a producer-distinct out-of-band identity
   check if no owner key is active, update the repository trust-root record,
   and independently provision the resulting anchor to every accepted-state
   verifier rather than loading it from this repository;
2. rerun the ADR gate only after that trust-root record is final and capture
   the resulting proposed composite payload digest;
3. present this ADR, its machine-readable decision, trust-root identity, and
   exact digest to the project owner;
4. receive explicit approval of that exact payload;
5. sign the domain-separated approval preimage that binds the exact approval
   text hash, timestamp, key ID, and approved payload digest;
6. record the exact approval text, timestamp, key ID, signature, preimage
   digest, and approved payload digest;
7. change both decision files to `accepted` and
   `implementation_authorized=true`;
8. rerun the gate in `--require-authorized` mode;
9. rerun the public E2E against the same independently provisioned anchor and
   the accepted-state online source snapshots;
10. retain the producer-distinct approval handoff bundle.

Any later trust-root enrollment, rotation/revocation, or content change outside
the normalized approval/status regions changes the payload digest and requires
renewed approval. The gate normalizes only the decision
`status`/`implementation_authorized`/`approval` fields and the three marked ADR
state regions, so those acceptance-state writes do not create a signature
cycle.

The repository record proves content consistency, not speaker identity. A
producer can mechanically construct a syntactically complete approval object,
so the gate must never call that alone authenticated project-owner approval.
Accepted state requires an Ed25519 signature under the independently enrolled,
non-revoked project-owner key over a domain-separated canonical payload that
includes this ADR, the decision JSON, the authoritative plan, both split
contracts, the trust root, the gate wrapper, strict validator, and public E2E
verifier. The repository enrollment record must match an external anchor
chosen by the verifier; a caller cannot make an arbitrary repository key
trusted by pointing the gate back at that same repository. Before
closure, a producer-distinct reviewer also compares the signed text and digest
with the external project-owner authorization and records that comparison in
the immutable handoff bundle. An enrolled owner key may exist while the ADR
remains proposed; no signed approval or implementation authorization exists
until the exact post-enrollment payload is approved.
