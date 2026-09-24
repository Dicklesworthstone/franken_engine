# ADR-0013: Ratify the Native WebAssembly Runtime Lane

- Status: Proposed — explicit project-owner approval is required
- Date proposed: 2026-09-24
- Decision authority: project owner (requested 2026-09-22: "Ratify via ADRs")
- Governing bead: `bd-9vouw.12`

> [!IMPORTANT]
> Not accepted. The facts in *Context* are measured from the source tree; the
> *Decision* section is a recommendation. The verification this ADR requires
> has **not** been run yet (see the last section).

## Context

- `crates/franken-engine/src/wasm_numeric_vm{.rs,/}`, `src/wasm_runtime_lane{.rs,/}`
  and `src/bin/franken_wasm_numeric.rs` hold about 19k lines of Rust, with
  about 24k lines of integration tests in roughly 30 `tests/wasm_*.rs` files
  and a CI workflow, `.github/workflows/native-wasm.yml`.
- Before 2026-09-15 the lane was about 6k lines whose runtime could only
  return constants (`bd-sde5e.6.2`). The growth came from 57 commits between
  2026-09-15 and 2026-09-19 made through the GitHub web identity; 31 of them
  say Cargo was unavailable and the change was unverified pending CI, and none
  cites a bead. It adds structured control flow, linear memory, tables, tail
  calls, host imports with replay, a cooperative scheduler, memory and work
  pools, tenant fuel partitions and WASI preview1 (streams, clocks, entropy,
  read-only files, descriptors, commands).
- The lane is not a JavaScript feature: there is no `WebAssembly` global;
  `module_resolver.rs` (`apply_wasm_module_contract`) only tags `.wasm`
  modules with Wasm syntax and extra required capabilities; the lane's module
  header describes it as an embedding API rather than JavaScript import
  evaluation; and the README lists WebAssembly as "Out of scope for the JS
  lane".
  The plan has no WebAssembly section. The only related bead,
  `bd-cixqu.16.3` (wire `.wasm` through the JS loader), is blocked.

## Decision (recommended)

1. **Purpose.** Ratify the lane as an *embedding API* for running untrusted
   compute modules under the same host-effect, replay and containment
   machinery as JavaScript extensions. Name its consumers explicitly in the
   plan (candidates: agent-sandbox tool plugins, franken_node native-addon
   replacement); a lane with no named consumer is frozen, not extended.
2. **Relationship to the JS lane.** Keep it separate. No `WebAssembly` JS
   global in the ES2020 conformance scope; `bd-cixqu.16.3` stays blocked
   until a consumer needs it.
3. **Security model.** Every host import and WASI call goes through the same
   hostcall capability registry (registered tag, declared authority, result
   contract) and host-effect journal as JavaScript hostcalls, so capability
   profiles, IFC labels, guardplane decisions and evidence receipts apply
   unchanged. The lane-specific quota and revocation mechanisms are wired to
   the shared containment path rather than kept parallel (see ADR-0015 item 3).
4. **Verification.** The unverified September commits are re-verified by a
   full crate check, clippy and test run on the pinned toolchain, with run
   ids recorded on the governing bead. The official WebAssembly spec test
   suite at a pinned revision is the conformance source.
5. **Ownership.** Add a plan section and an owning epic bead; list what is
   explicitly out of scope (threads, SIMD, GC proposal, the JS API).

## Alternatives considered

- **Remove the lane.** Rejected without a measured reason: it has extensive
  tests and a plausible consumer, and deleting it needs an owner decision
  under AGENTS.md Rule 1.
- **Expose it to JavaScript now.** Rejected: outside the ES2020 target and no
  consumer asks for it.

## Verification owed before acceptance

- Not yet run: `cargo test -p frankenengine-engine --test 'wasm_*'` and the
  lane's lib tests on the pinned toolchain. An attempt on 2026-09-24 was
  cancelled because the build host's disk was full; local builds on that host
  are now routed to remote workers.
- A `scripts/e2e/wasm_lane_smoke.sh` that builds the lane and runs a numeric
  module, a WASI command with stdout capture, a host import denied by
  capability policy, a quota exhaustion and a replayed host effect, writing
  JSONL per step (module sha256, expected, observed, verdict, duration).
