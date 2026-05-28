# Conformance Goldens — Regeneration Workflow

> Bead: [bd-vm7u4](https://) (FIND-11) / parent
> [bd-85qfs](https://) — Conformance test harness audit (ScarletJay,
> 2026-05-28). Audit found no documented `UPDATE_GOLDENS`-style path
> for the conformance harnesses (they're all hand-authored today); this
> is the canonical "how do I update an expected output?" recipe.

## State of the world

Unlike the general golden suite under `tests/golden/` — which honors
the project-wide `UPDATE_GOLDENS=1 cargo test ...` contract
(bd-ub6x8.2) and sweeps `.actual` siblings on a successful match
(bd-ub6x8.7) — the conformance corpora are **fully hand-authored**.
There is no environment-variable bless flow today. Specifically:

- `tests/conformance/transplanted/` — `fixture.json` + `expected.txt`
  pairs are hand-authored from upstream test262 cases reconciled
  against `tests/test262_conformance_pins.toml`.
- `tests/conformance/ifc_corpus/` — `fixture.json` + `expected.txt`
  pairs are hand-authored against the IFC policy semantics. The
  supporting `ifc_conformance_assets.json` (~168 KB consolidated
  decision-trace) IS rebuildable from the engine, but only via a
  hand-run script — not via `UPDATE_GOLDENS=1`.
- `tests/conformance/frx_react_corpus/` — `fixture.json` + `trace.json`
  pairs are hand-authored against canonical React behaviors; the
  lockstep oracle compares byte-for-byte.
- `tests/conformance/proof_artifact/` — see the corpus's own
  `README.md`; same hand-authored discipline.

This is intentional: a conformance corpus that quietly re-blesses
itself when the engine drifts defeats its own purpose. The price is
that authoring a new case or updating an expected output is
deliberate manual work — that's the *point*.

## Updating an existing expected output

When the engine deliberately changes behavior (with a tracking bead
and review), update the matching expected file by hand:

### transplanted/

1. Edit the `fixtures/<case>.fixture.json` if the input also changes.
2. Edit `expected/<case>.expected.txt` to the new canonical output.
3. Run the harness:
   `cargo test -p frankenengine-engine --test conformance_assets`
4. If a behavior was changed but the new output is *not* what the
   spec says, the right move is one of:
   - File a `tracking_bead` waiver in `conformance_waivers.toml`
     (see [`CONFORMANCE_WAIVERS_GUIDE.md`](CONFORMANCE_WAIVERS_GUIDE.md)) and
     leave the expected unchanged until the engine catches up.
   - File an entry in the future top-level ES2020 `DISCREPANCIES.md`
     (bd-w50mz / FIND-4) if the divergence is intentional and
     permanent.

### ifc_corpus/

1. Edit the `fixtures/<case>.fixture.json` and `expected/<case>.expected.txt`.
2. If the policy lattice or receipt-verifier schema changed,
   `ifc_conformance_assets.json` may also need to be rebuilt — see
   the recipe in `tests/ifc_release_gate.rs`.
3. Run both consumers:
   `cargo test -p frankenengine-engine --test ifc_release_gate --test ifc_conformance_corpus`

### frx_react_corpus/

1. Edit the paired `fixtures/<scenario>.fixture.json` AND
   `traces/<scenario>.trace.json`. Both must change together — the
   lockstep oracle treats the trace as the canonical expectation.
2. Run the harnesses:
   `cargo test -p frankenengine-engine --test frx_lockstep_oracle --test frx_canonical_react_behavior_corpus --test frx_ssr_hydration_rsc_compatibility_strategy`

## Adding a new case

See the per-corpus `PROVENANCE.md` for the layout convention and the
naming scheme that the auto-discovery in each harness expects:

- `tests/conformance/transplanted/PROVENANCE.md`
- `tests/conformance/ifc_corpus/PROVENANCE.md`
- `tests/conformance/frx_react_corpus/PROVENANCE.md`

After adding a case, append a row to the corpus's inventory table in
that `PROVENANCE.md` so future grep-ability stays honest.

## Why no `UPDATE_GOLDENS`?

Three reasons:

1. **Adversarial bytes.** test262 cases are sometimes specifically
   designed to surface engine bugs (e.g., spec corner cases the
   engine gets wrong). An auto-bless flow would silently lock in the
   bug.
2. **Lockstep semantics.** `frx_react_corpus/` traces are byte-for-byte
   comparisons against a canonical React execution — an auto-bless
   would silently lock in whatever the runtime emitted on the last run.
3. **Audit trail.** Conformance changes show up in `git log` as
   explicit edits to specific cases, not as a hash diff of an
   auto-blessed blob. That's load-bearing for the rotation engineer
   reviewing the cumulative trend.

If a future use case demands an auto-bless flow for a specific
sub-corpus (e.g., a brand-new harness whose expectations track an
engine-internal serializer), the right move is to:

- File a follow-up bead under [bd-85qfs](https://).
- Decide *per-corpus* whether `UPDATE_GOLDENS=1` is acceptable for
  that corpus.
- Wire it up using the `tests/_support/golden_diag.rs::GoldenDiag`
  helper (the same one the general golden suite uses post-bd-ub6x8.3).

## Related Docs

- `tests/conformance/PROVENANCE.md` — corpora overview.
- `CONFORMANCE_WAIVERS_GUIDE.md` — waiver operator guide.
- `TEST262_REFRESH_POLICY.md` — upstream pin refresh cadence.
- `tests/golden/PROVENANCE.md` — the *other* golden tree (the one
  that DOES honor `UPDATE_GOLDENS=1`).
