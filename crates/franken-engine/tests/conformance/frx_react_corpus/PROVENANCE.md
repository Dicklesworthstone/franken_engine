# `frx_react_corpus/` — React-Compat Conformance Scenarios

> Parent: [`tests/conformance/PROVENANCE.md`](../PROVENANCE.md) /
> bead [bd-m8aeb](https://) (FIND-24).

## Purpose

Hand-authored React-compatibility scenarios that exercise the
canonical React behaviors the franken-engine FRX runtime must match.
Each case ships an input `fixture.json` (component tree + scheduled
events) and a paired `trace.json` capturing the canonical hook /
render / commit ordering the engine must reproduce.

Categories covered include: hook ordering, effect lifecycle (parent /
child cleanup), error boundary capture, event capture/bubble/stop,
hydration mismatch handling, rendering / DOM snapshot, portal + ref
forwarding edges, RSC server-component hook violations, SSR
streaming + Suspense handoff, state batching, and concurrent reveal
transitions.

## Owning Tests

- `crates/franken-engine/tests/frx_lockstep_oracle.rs` — lockstep
  oracle: replays each fixture in the FRX runtime and asserts the
  resulting trace matches the paired `trace.json` byte-for-byte.
- `crates/franken-engine/tests/frx_canonical_react_behavior_corpus.rs`
  — corpus-coverage gate.
- `crates/franken-engine/tests/frx_ssr_hydration_rsc_compatibility_strategy.rs`
  — SSR-specific subset (hydration + RSC violations).
- `crates/franken-engine/tests/frx_test_logging_schema.rs` —
  validates trace shape against the structured-log schema.

## Layout

```
frx_react_corpus/
  fixtures/   # 12 *.fixture.json — component graph + event schedule
  traces/     # 12 *.trace.json   — paired canonical traces
```

Pairing is by basename: `compat.hooks.order.state_effect_memo_ref.fixture.json`
pairs with `compat.hooks.order.state_effect_memo_ref.trace.json`.

## Fixture Inventory

12 paired scenarios:

| Scenario                                                       | Subject                                  |
|----------------------------------------------------------------|------------------------------------------|
| `compat.effects.lifecycle.parent_child_cleanup`                | effect cleanup ordering across nesting   |
| `compat.errors.boundary.capture_recover`                       | error boundary capture + recovery        |
| `compat.events.dispatch.capture_bubble_stop`                   | event capture/bubble + stopPropagation   |
| `compat.hooks.order.reducer_context_transition`                | reducer + context hook ordering          |
| `compat.hooks.order.state_effect_memo_ref`                     | state / effect / memo / ref hook order   |
| `compat.hydration.server_client_mismatch`                      | SSR hydration mismatch handling          |
| `compat.render.dom_snapshot_basic`                             | baseline DOM snapshot rendering          |
| `compat.render.portal_ref_forwarding_edge`                     | portal + ref-forwarding interaction      |
| `compat.rsc.server_component_hook_violation`                   | RSC server-component hook violation      |
| `compat.ssr.streaming.suspense_handoff`                        | SSR streaming + Suspense handoff         |
| `compat.state.batching.microtask_transition`                   | microtask state batching                 |
| `compat.suspense.transitions.concurrent_reveal`                | concurrent Suspense reveal               |

## Regeneration

Hand-authored — no auto-regen flow exists today. To add or update a
scenario:

1. Edit the `<name>.fixture.json` + `<name>.trace.json` pair (the
   trace is the canonical expected output; both must change together
   when behavior is intentionally adjusted).
2. Run the lockstep oracle and corpus gate:
   `cargo test -p frankenengine-engine --test frx_lockstep_oracle
   --test frx_canonical_react_behavior_corpus`.
3. Any byte-for-byte trace drift fails the oracle — re-bake intentionally
   only after reviewing the diff.
