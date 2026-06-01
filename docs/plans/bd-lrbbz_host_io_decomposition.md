# bd-lrbbz decomposition — sandboxed guest fs/network I/O surface (extension-host)

**Author:** ScarletOrchid · 2026-05-30 · Status: PLAN (first slice pending)

## Confirmed architecture (verified before filing)
- **Dependency direction:** `franken-engine` depends on `frankenengine-extension-host`
  (`crates/franken-engine/Cargo.toml:259  frankenengine-extension-host = { path = "../franken-extension-host" }`).
  Extension-host does **not** depend on engine. ⇒ The host I/O trait + types live in
  **extension-host** (the lower crate); the engine routes *down* to a trait object. No circular dep.
- **Engine seam (where routing plugs in):** `crates/franken-engine/src/algebraic_effects.rs`
  — `EffectError::CapabilityDenied` (294), `handle_effect()` (420), and the bd-6wc97/1ac8fabe
  explicit-deny fs/network paths at ~1268 and ~1305. Today these unconditionally `Err(CapabilityDenied)`.
- **Capability model (extension-host/src/lib.rs):** manifest `enum Capability` @79 (FsRead, FsWrite, …);
  runtime effect-capability enum @~2051 (FsRead, FsWrite, NetworkSend, NetworkRecv, TimerCreate, IpcSend, ProcessSpawn).
- **Reusable primitives:** replay recording — `hostcall_effects_migration.rs`, `callback_stdlib_dispatch.rs`;
  IFC labeling — `flow_lattice.rs`, `ifc_label_translation_validator.rs`, `unified_authority_algebra.rs`.
- **extension-host deps:** serde, serde_json, serde_bytes, sha2, ed25519-dalek (std only otherwise; `#![forbid(unsafe_code)]`).

## Security invariant (non-negotiable)
Engine never performs guest I/O (AGENTS.md split contract). Until a real sandboxed provider lands,
the default provider **fail-closed denies** everything — preserving the bd-6wc97/1ac8fabe explicit-deny posture.
Option A (host std::fs/network under the in-engine capability gate) was REJECTED by bd-6wc97.1 as a sandbox escape.

## Dependency-ordered sub-beads

- **bd-lrbbz.1 — Host I/O interface surface (FIRST SLICE).** In extension-host: define
  `HostIoRequest` (FsRead/FsWrite/NetworkSend/NetworkRecv), `HostIoResponse`, `HostIoError`
  (Denied/CapabilityMissing/NotImplemented/SandboxViolation/Io — all fail-closed), the
  `HostIoProvider` trait, and `DenyAllHostIo` (default; denies every request with a stable reason).
  Each request exposes `required_capability()`. NO real I/O. Self-contained (std+serde). Unit tests:
  deny-all returns Denied for every request kind; required_capability mapping; serde round-trip.
  **No dependencies — shippable now.**

- **bd-lrbbz.2 — Engine routing seam.** Thread an optional `Arc<dyn HostIoProvider>` into the
  effect handler; at the algebraic_effects.rs fs/network deny sites, route to the provider **iff**
  (a) one is installed AND (b) the capability is granted — else keep `CapabilityDenied`. Default
  (no provider) stays fully fail-closed. Depends on **.1**.

- **bd-lrbbz.3 — Deterministic-replay recording.** Record each host I/O (request, response/err) to the
  replay log; in replay mode return recorded responses instead of calling the provider. Reuse
  `hostcall_effects_migration` primitives. Depends on **.2**.

- **bd-lrbbz.4 — IFC labeling.** Label data returned from fs/network reads as tainted via `flow_lattice`
  so downstream flow tracking holds. Depends on **.2** (and **.3** for replay-of-labels).

- **bd-lrbbz.5 — Sandboxed real fs provider.** Real fs behind the trait with a path-jail/allowlist,
  enforcing the granted capability scope; fail-closed on any escape. Security-critical. Depends on **.1** (+**.2**).

- **bd-lrbbz.6 — Sandboxed real network provider.** Real network behind the trait with a host/port
  allowlist; fail-closed otherwise. Security-critical. Depends on **.1** (+**.2**).

Order: .1 → .2 → {.3, .4} ; .5/.6 require .1+.2. Supersedes the in-engine framing of bd-6wc97.2/.3.
