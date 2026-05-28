# Conformance Fixture Provenance — `tests/conformance/`

This directory holds the four conformance corpora the franken-engine
test suite consumes, plus the supporting metadata each one needs to be
auditable and reproducible. Each subdirectory ships its own
`PROVENANCE.md` (or already-shipped `README.md` / `COVERAGE.md` /
`DISCREPANCIES.md`) detailing fixture authorship, regen workflow, and
upstream pins where applicable.

> Bead: [bd-m8aeb](https://) (FIND-24) / parent
> [bd-85qfs](https://) — Conformance test harness audit (ScarletJay,
> 2026-05-28). Documentation gap surfaced by `/testing-conformance-harnesses`:
> only `proof_artifact/` shipped provenance docs before this pass.

## Corpora

| Subdir                                        | Origin                              | Owning test                                      | Provenance               |
|-----------------------------------------------|-------------------------------------|--------------------------------------------------|--------------------------|
| [`proof_artifact/`](proof_artifact/README.md) | hand-authored ES2020 proof-artifact | `tests/proof_artifact_release_gate.rs`           | ships `README.md` + `COVERAGE.md` + `DISCREPANCIES.md` |
| [`transplanted/`](transplanted/PROVENANCE.md) | hand-translated test262 case slices | `tests/conformance_assets.rs`                    | this commit              |
| [`ifc_corpus/`](ifc_corpus/PROVENANCE.md)     | hand-authored IFC scenarios         | `tests/ifc_release_gate.rs`, `tests/ifc_conformance_corpus.rs` | this commit |
| [`frx_react_corpus/`](frx_react_corpus/PROVENANCE.md) | hand-authored React-compat scenarios | `tests/frx_lockstep_oracle.rs`, `tests/frx_ssr_hydration_rsc_compatibility_strategy.rs`, `tests/frx_canonical_react_behavior_corpus.rs` | this commit |

## test262 Pinning

Upstream test262 vectors are not vendored verbatim into this tree — only
hand-translated case slices live under `transplanted/`. The upstream
commit they were last reconciled against is pinned in
`tests/test262_conformance_pins.toml`:

```toml
schema_version = "franken-engine.test262-pin.v1"
source_repo    = "tc39/test262"
es_profile     = "ES2020"
test262_commit = "d0c1b4555b03dd404873fd6422a4b5da00136500"
```

Loaded via `Test262PinSet::load_toml(...)` in
`tests/test262_release_gate.rs` and consulted by the per-harness
release gate as the canonical spec target.

## ECMA-262 Spec Target

The whole tree targets ECMA-262 **ES2020**. The
[`docs/CONFORMANCE_HARNESS_MANIFEST.md`](../../../../docs/CONFORMANCE_HARNESS_MANIFEST.md)
manifest declares the target conformance score (0.95) and the live
MUST-clause coverage budget (currently 0.67 for the baseline builtin
surface — gap tracked under bd-u2n6w / FIND-3).

A dedicated spec-target document and ES2020 `DISCREPANCIES.md` for the
overall corpus (separate from the per-corpus discrepancy notes shipped
under `proof_artifact/`) are tracked under bd-5kg0h (FIND-1),
bd-d9ot3 (FIND-18), and bd-w50mz (FIND-4) respectively.

## Regeneration Convention

Each corpus is hand-authored; there is no `UPDATE_GOLDENS=1`-style
auto-regen flow today (the missing `UPDATE_GOLDENS` recipe for
conformance harnesses is bd-vm7u4 / FIND-11). Authoritative bytes live
in the `*.fixture.json` / `*.expected.txt` pairs committed under each
corpus directory; the harnesses read them at test time and fail the
release gate on any drift.

## Adding a New Corpus

1. Create `tests/conformance/<corpus>/{fixtures,expected}/` (or the
   equivalent layout the harness expects — see the per-corpus
   provenance file for the convention).
2. Add a `PROVENANCE.md` to the new corpus directory listing: owning
   test path(s), fixture count, expected-byte authorship, regen
   command (or note that there is none), and the upstream source if
   one exists.
3. Wire the corpus into a `_conformance.rs` or `_release_gate.rs`
   harness so CI exercises it.
4. Append a row to the **Corpora** table above.
