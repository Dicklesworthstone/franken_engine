# `transplanted/` — Hand-Translated test262 Case Slices

> Parent: [`tests/conformance/PROVENANCE.md`](../PROVENANCE.md) /
> bead [bd-m8aeb](https://) (FIND-24).

## Purpose

A small, hand-translated subset of test262 case behaviors that the
franken-engine baseline interpreter must match deterministically.
Each fixture is a JSON record describing the source program, the
expected stdout/stderr/exit-class, and any harness-specific metadata
the consumer asserts on. The `.expected.txt` sibling holds the
canonical expected output the harness compares against.

## Owning Tests

- `crates/franken-engine/tests/conformance_assets.rs`
  (consumes `transplanted/conformance_assets.json` plus per-case
  `*.fixture.json` / `*.expected.txt` pairs).

## Upstream Pin

The behaviors transplanted here are reconciled against the test262
commit pinned in `tests/test262_conformance_pins.toml`
(`d0c1b4555b03dd404873fd6422a4b5da00136500`, es_profile `ES2020`).
This corpus is NOT a verbatim copy of upstream cases — each fixture is
hand-authored to exercise the same observable behavior at the
franken-engine surface, so reformatting / wrapper changes that don't
alter semantics may diverge from upstream layout without a refresh.

## Fixture Inventory

10 case slices, each shipping a `<name>.fixture.json` +
`<name>.expected.txt` pair under `fixtures/` and `expected/`:

| Case                         | Subject under test                                          |
|------------------------------|-------------------------------------------------------------|
| `async_await_ordering`       | async/await microtask ordering                              |
| `closure_capture`            | closure variable capture semantics                          |
| `destructuring_binding`      | destructuring binding patterns                              |
| `error_handling`             | try/catch/finally control flow                              |
| `generator_lifecycle`        | generator function lifecycle (init / yield / return / throw)|
| `iterator_protocol`          | `Symbol.iterator` consumer protocol                         |
| `module_namespace_binding`   | module namespace object binding                             |
| `promise_resolution`         | promise resolution + chaining                               |
| (plus one additional fixture not listed here — `ls fixtures/` for the live count)         |

## Regeneration

Hand-authored — no auto-regen flow exists today. To add or update a
fixture:

1. Edit the `fixture.json` + `expected.txt` pair.
2. Run `cargo test -p frankenengine-engine --test conformance_assets`.
3. If a behavior is changed deliberately, also update the relevant
   row in the future top-level `DISCREPANCIES.md` (tracked under
   bd-w50mz / FIND-4).

## Adding a New Case

1. Pick a target test262 case ID (the
   `tests/test262_conformance_pins.toml` commit is authoritative for
   what's in scope).
2. Author `fixtures/<case>.fixture.json` + `expected/<case>.expected.txt`.
3. Append the case ID + subject to the inventory table above.
4. Re-run the owning test.
