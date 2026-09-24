# ADR-0015: Extension-Host Real Network and Process I/O

- Status: Proposed — explicit project-owner approval is required
- Date proposed: 2026-09-24
- Decision authority: project owner (requested 2026-09-22: "Ratify via ADRs")
- Governing bead: `bd-9vouw.14` (depends on `bd-9vouw.7`, guardplane in-flight
  containment)

> [!IMPORTANT]
> Not accepted. The facts in *Context* are verified against the source; the
> *Decision* section is a recommendation.

## Context

- `crates/franken-extension-host` performs real host effects:
  `src/host_io.rs` plus its submodules (`control`, `http_response`,
  `network_deadline/{resolver, connection_race, revocation}`) run OS DNS on
  bounded worker threads, dual-stack TCP connection racing and rustls 0.23
  TLS with webpki roots; `src/process_spawn.rs` spawns real processes and kills
  process groups. About 14k lines in total.
- Origin: a1fb5b3b7 (2026-06-18, `bd-lrbbz.7` / `bd-6wc97`); the `bd-lrbbz`
  epic still reads DEFERRED. TLS arrived through franken_node `bd-3894s`. The
  September DNS / IPv6 / connection-racing / pinned-HTTPS / in-flight
  revocation commits cite no bead.
- Guest JavaScript reaches the network mechanism: `http.get` and `fetch` lower
  to the engine's `net:request` hostcall, and `ClientRequest.end()` issues the
  same `NetworkRequest` (`baseline_interpreter.rs`, `dispatch_host_io_hostcall`).
  The provider doc comment that said no guest path reached it was stale and
  was corrected alongside this draft.
- The provider is a mechanism with no destination policy: it performs no SSRF,
  allowlist or DNS-rebinding check and trusts callers to have authorized the
  endpoint. franken_node wraps it in `SsrfGatedHostIo` and `FlowGatedHostIo`
  before installing it; `frankenctl agent-sandbox` installs `SandboxedHostIo`
  directly. **An extension holding the network capability under
  `frankenctl agent-sandbox` therefore has unrestricted egress**, bounded only
  by the capability tag and the static IFC pass.
- Work-scope revocation is supervisor-driven (embedders call the kill switch).
  Neither the guardplane nor `ContainmentExecutor` can trigger it, and a
  revocation produces typed cancellations and effect-journal entries, not
  guardplane decision receipts: it is a second, unconnected containment path.

## Decision (recommended)

1. **Ownership.** The I/O *mechanisms* (DNS, TCP, TLS, process spawn,
   in-flight revocation) stay in `franken-extension-host`; `bd-lrbbz` and
   `bd-6wc97.1` are reconciled to that and closed or re-scoped with evidence.
2. **Destination policy fails closed in the engine.** `SandboxedHostIo` no
   longer performs network effects without an explicit destination policy
   supplied at construction. Embedders without franken_node (agent-sandbox,
   `frankenctl`) get deny-all-network by default and opt in per destination;
   franken_node keeps supplying its SSRF policy. The mechanism/policy split
   stays, but the unsafe default goes away.
3. **One containment path.** Guardplane decisions (from `bd-9vouw.7`) can
   trigger work-scope revocation, and every revocation or denial writes an
   evidence-ledger receipt linked to the trace, decision and policy ids, so the
   same decision is visible to replay and to the operator.
4. **Verification.** Network tests run hermetically on loopback (local TCP and
   TLS servers) in CI. The unreferenced September commits are re-verified by a
   full crate check, clippy and test run on the pinned toolchain, with the run
   ids recorded on the governing bead.

## Alternatives considered

- **Move the mechanisms into franken_node.** Rejected: the engine's replay
  journal and capability dispatch need them, and agent-sandbox would lose I/O.
- **Keep the provider policy-free and document the risk.** Rejected: a
  permissive default for an adversarial-extension runtime contradicts the
  project's fail-closed contract.

## Consequences

- `frankenctl agent-sandbox` runs that need egress must name destinations.
- Guardplane in-flight containment (`bd-9vouw.7`) becomes a prerequisite for
  item 3, and runtime IFC egress checks (`bd-9vouw.8`) apply to these effects.

## Verification owed before acceptance

- Hermetic loopback end-to-end check: allowed request, capability-denied
  request, IFC-denied request (Secret body), guardplane-triggered revocation
  mid-request, and a revoked scope's next effect refused, with JSONL per step
  and the evidence-ledger entry id for each denial or revocation.
- `revocation_inside_a_real_host_call_stops_the_next_effect` passing in CI.
