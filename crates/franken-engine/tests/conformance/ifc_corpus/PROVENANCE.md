# `ifc_corpus/` — IFC Conformance Scenarios

> Parent: [`tests/conformance/PROVENANCE.md`](../PROVENANCE.md) /
> bead [bd-m8aeb](https://) (FIND-24).

## Purpose

Hand-authored Information Flow Control (IFC) scenarios covering
the security-relevant decision lattice the engine must enforce: benign
flows, declassification exceptions, and the five exfiltration vectors
the policy receipt verifier must reject (`direct`, `indirect`,
`implicit`, `covert`, `temporal`). Each fixture asserts both the
expected stdout AND the security verdict — a benign case that emits
an exfil-like decision fails the harness just as hard as an exfil case
that gets allowed.

## Owning Tests

- `crates/franken-engine/tests/ifc_release_gate.rs` — release-gate
  consumer (one of the conformance ratchets surfaced in
  CI).
- `crates/franken-engine/tests/ifc_conformance_corpus.rs` — per-case
  driver, picks up everything under `fixtures/` automatically.

## Supporting Asset

`ifc_conformance_assets.json` (sibling file in this directory) is a
~168 KB consolidated decision-trace artifact that the harness loads
alongside the per-case fixtures. Regenerated when the lattice or
receipt-verifier schema changes — see the owning tests for the
regen recipe.

## Fixture Inventory

8 hand-authored cases, each shipping a `<name>.fixture.json` +
`<name>.expected.txt` pair under `fixtures/` and `expected/`:

| Case                            | Vector / Subject                                |
|---------------------------------|--------------------------------------------------|
| `benign_allow`                  | baseline: capability granted, flow stays in zone |
| `benign_dual_cap`               | dual-capability authorisation flow               |
| `benign_non_sensitive_network`  | network egress with non-sensitive payload        |
| `declass_exception`             | explicit declassification path                   |
| `exfil_covert`                  | covert-channel exfiltration (timing/cache)       |
| `exfil_direct`                  | direct exfiltration (sensitive → public sink)    |
| `exfil_implicit`                | implicit flow via control dependence             |
| `exfil_indirect`                | indirect flow via data dependence                |
| `exfil_temporal`                | temporal-correlation exfiltration                |

## Regeneration

Hand-authored — no auto-regen flow exists today. To add or update a
case:

1. Edit the `fixture.json` + `expected.txt` pair under
   `fixtures/` and `expected/`.
2. If the lattice or receipt schema changed, also rebuild
   `ifc_conformance_assets.json` per the recipe in the owning
   release-gate test.
3. Run `cargo test -p frankenengine-engine --test ifc_release_gate
   --test ifc_conformance_corpus`.
