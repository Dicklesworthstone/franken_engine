# ADR-0014: The Engine Owns Node Builtin-Module Semantics

- Status: Proposed — explicit project-owner approval is required
- Date proposed: 2026-09-24
- Decision authority: project owner (requested 2026-09-22: "Ratify via ADRs")
- Governing bead: `bd-9vouw.13`
- Supersedes on acceptance: the "Node/Bun compatibility surface" line of
  `docs/REPO_SPLIT_CONTRACT.md` and the second sentence of
  `docs/RUNTIME_CHARTER.md` §1, both of which must be edited in the same change
  that accepts this ADR (and the matching franken_node split contract).

> [!IMPORTANT]
> Not accepted. Nothing below changes ownership until the owner accepts it.
> The facts in *Context* are measured; the *Decision* section is a
> recommendation.

## Context

The written contracts and the code disagree.

- `docs/REPO_SPLIT_CONTRACT.md` gives franken_node the "Node/Bun compatibility
  surface"; `docs/RUNTIME_CHARTER.md` §1 gives it "product compatibility UX";
  plan §9 Phase D puts "process/fs/network/child-process compatibility layers"
  in franken_node.
- The code does the opposite. franken_engine implements the semantics of
  `fs`, `fs/promises`, `path`, `events`, `stream`, `stream/promises`, `crypto`,
  `child_process`, `cluster`, `zlib`, `http`, `https`, `net`, `tls`, `dgram`,
  `os`, `url`, `querystring`, `timers`, `timers/promises`, `buffer` and
  `process`: about 22.6k lines inside `src/baseline_interpreter.rs`, about 10k
  lines of Node-shaped lowering in `src/lowering_pipeline.rs` (recognized
  `require()` specifiers are elided into direct `builtin:*` hostcalls), and
  about 14k lines of host I/O in `franken-extension-host` (`host_io`,
  `process_spawn`). The owning beads (`bd-fw7zd`, `bd-x85a7`, `bd-53l89`,
  `bd-asw4m`, `bd-zco6t`) are follow-ups filed from franken_node compat-corpus
  beads.
- The structural reason: the engine exposes no API through which the product
  could supply builtin modules, and every builtin needs engine internals that a
  product layer cannot reach — the hostcall capability registry
  (`capability.rs` `hostcall_registry_row`), static IFC result/exception
  contracts in lowering, deterministic replay journaling of host effects, and
  the ambient-authority membrane.

Measured conformance at this revision (franken_node compat corpus, lockstep
Node v22.2.0 + Bun 1.4.2 + product triad, real run 2026-09-24 against
franken_engine `0dce0e734`; overall 489/560 = 87.32%):

| Family | Pass | Note |
|---|---|---|
| buffer | 30/30 | |
| child_process | 0/30 | this host lacks the bubblewrap containment unit (franken_node `bd-at11s`); not an engine verdict |
| cluster | 18/20 | |
| crypto | 31/45 | 13 are IFC refusals by contract (crypto results/exceptions are TopSecret) |
| events | 30/30 | |
| fs | 48/50 | |
| http | 49/50 | |
| net | 39/40 | |
| os | 30/30 | |
| path | 35/35 | |
| querystring | 20/20 | |
| stream | 44/65 | 12 IFC refusals, 9 of them ESM fixtures importing an opaque local harness (`bd-cx8gb`) |
| timers | 30/30 | |
| tls | 40/40 | |
| url | 25/25 | |
| zlib | 20/20 | |

`dgram`, `https`, `fs/promises`, `stream/promises`, `timers/promises` and
`process` have no dedicated corpus family yet.

## Decision (recommended)

1. **Ownership.** The engine owns the *semantics* of every Node builtin
   module that executes guest callbacks or performs a host effect, because
   those semantics are inseparable from capability dispatch, IFC labeling and
   replay. franken_node owns the product CLI and UX, package/module resolution
   outside builtins, operator policy configuration (e.g. SSRF policy,
   TLS trust anchors), the compatibility corpus and its gate, and the host
   provider wiring it installs into the engine. Rule for a new module: if it
   needs a capability tag, an IFC contract or a replay journal entry, it is
   engine-owned; a pure-JS utility module with none of those may ship from the
   product as guest code.
2. **Location.** No new builtin module lands in `baseline_interpreter.rs`.
   New modules go behind a per-module boundary (for example
   `src/node_builtins/<module>.rs`) that declares its hostcall tags and result
   contracts; existing modules move there as part of the BRIDGE-01
   decomposition (`BRIDGE-01.6` / `01.7`), not in a separate refactor.
3. **Security contract.** Every builtin effect goes through a registered
   hostcall tag with a declared authority and result contract (unregistered
   tags already fail closed at lowering), exceptions carry the provider's
   authenticated `HostIoExceptionProvenance`, and every performed effect is
   recorded in the host-effect journal so strict replay reproduces it.
4. **Conformance authority.** The franken_node lockstep corpus is the
   authority for Node-observable behavior; Node's own `test/parallel` files
   are the source for new fixtures. Corpus failures carry an
   `investigation_bead_id`; engine-side causes get an engine bead that the
   product bead depends on.

## Alternatives considered

- **Move the modules into franken_node.** Rejected for now: impossible without
  a builtin-module provider API on the engine, and it would split one
  security decision (capability + IFC + replay) across two repositories.
- **Keep the status quo without an ADR.** Rejected: the written contract then
  keeps contradicting the code, and new modules keep deepening the monolith.

## Consequences

- The split contract, the charter §1, plan §9 Phase D, the README split
  text and franken_node's split contract are updated together on acceptance.
- Module additions carry capability, IFC and replay work up front, which is
  slower per module but is the only path that keeps the security claims true.

## Verification owed before acceptance

- Per-module end-to-end check through franken_node's run path (not
  `frankenctl run`: its deny-all ambient authority refuses `require()` of
  builtins by design), one program per module compared with Node, JSONL per
  module. The corpus table above covers 16 of 22 modules.
- Baselines for the six modules without a corpus family.
