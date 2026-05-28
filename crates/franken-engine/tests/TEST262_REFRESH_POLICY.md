# test262 Fixture Refresh Policy

> Bead: [bd-rpimp](https://) (FIND-23) / parent
> [bd-85qfs](https://) — Conformance test harness audit (ScarletJay,
> 2026-05-28). Audit found no documented refresh cadence for the
> `tests/test262_conformance_pins.toml` commit pin; this is the
> policy.

## Pin file

The whole test262-reconciled corpus tracks a single upstream commit
pinned in:

```
crates/franken-engine/tests/test262_conformance_pins.toml
```

```toml
schema_version  = "franken-engine.test262-pin.v1"
source_repo     = "tc39/test262"
es_profile      = "ES2020"
test262_commit  = "d0c1b4555b03dd404873fd6422a4b5da00136500"
```

Loaded at gate-evaluation time by
`tests/test262_release_gate.rs` via
`Test262PinSet::load_toml(...)`. The commit string is the *canonical
authority* for what spec behaviors the engine is currently asserting
against; any test262 case behavior referenced inside
`tests/conformance/transplanted/` is reconciled against this commit.

## Refresh cadence

The pin should be advanced on **a quarterly cadence** OR **whenever a
specific upstream change motivates it** (whichever comes first):

- **Quarterly (default):** at the start of each calendar quarter, an
  operator (or the conformance-rotation engineer) advances the pin to
  the head-of-main test262 commit that day, runs the full release
  gate, and files follow-up beads for any newly-failing case.
- **Event-triggered:** advance the pin sooner if (a) an upstream
  test262 fix lands that materially changes our score on an existing
  case we already cover, or (b) we ship a new engine feature that
  enables a chunk of cases that were previously waived as
  `not_yet_implemented`.

The cadence is intentionally conservative — test262 ships hundreds of
new cases per quarter, and the cost of advancing the pin is roughly
proportional to "how many newly-failing transplanted cases need
investigation." A monthly cadence is acceptable but not required; a
yearly cadence is too long (the pin and the spec drift).

## Refresh procedure

1. **Snapshot the current state.**
   - `git log -1 --format="%H %s" -- crates/franken-engine/tests/test262_conformance_pins.toml`
   - Record the current pin and the date in the bead the refresh runs
     under.

2. **Pick the new commit.**
   - Default: `git ls-remote https://github.com/tc39/test262 main` →
     latest commit on `main`. Pin to the same `es_profile`
     (`ES2020`) unless this refresh is also a profile upgrade.
   - If a specific upstream fix motivates the refresh, pin to the
     commit that includes that fix (not necessarily HEAD).

3. **Update the pin file.**
   - Edit `tests/test262_conformance_pins.toml` to the new
     `test262_commit`. Leave `schema_version` and `source_repo`
     unchanged.

4. **Run the gate.**
   - `cargo test -p frankenengine-engine --test test262_release_gate`
   - `cargo test -p frankenengine-engine --test conformance_assets`
   - Any new failure is either (a) a case that was already failing
     and is now newly *visible* (the upstream test got a stricter
     assertion), (b) a genuine engine regression, or (c) a new
     transplanted case we need to author.

5. **Triage.**
   - For each new failure, decide: fix the engine, add a transplanted
     case, or file a waiver (see [`CONFORMANCE_WAIVERS_GUIDE.md`](CONFORMANCE_WAIVERS_GUIDE.md)).
   - File a tracking bead for every waiver added.

6. **Refresh sibling docs.**
   - Bump the `test262_commit` reference in
     `tests/conformance/PROVENANCE.md` and
     `tests/conformance/transplanted/PROVENANCE.md` to match.
   - If any waiver expired during the refresh, remove it (the gate
     would otherwise fail closed at first run anyway).

7. **Commit.**
   - One commit per refresh: pin change + sibling-doc bumps + waiver
     additions/removals together, so `git log` is the audit trail.

## Who runs the refresh

The conformance-rotation engineer (currently the team listed under
`reviewer = "runtime-conformance"` in the waiver registry). Other
agents may run an opportunistic refresh if they're already in the
test262 surface, but they MUST file the tracking bead and tag the
rotation engineer in it.

## Out of scope

- **Annex B vectors** are out of scope until [bd-d9ot3](https://)
  (FIND-18) decides on the conformance-targets scope.
- **ECMA-402 (i18n)** vectors are similarly out of scope.
- **Web-platform tests** (not test262) are tracked separately under
  the `frx_react_corpus/` harness.

## Related Docs

- `tests/conformance/PROVENANCE.md` — corpora the pin governs.
- `CONFORMANCE_WAIVERS_GUIDE.md` — waiver operator guide
  (bd-r2vw9 / FIND-19).
- `CONFORMANCE_GOLDENS_REGEN.md` — UPDATE_GOLDENS path
  (bd-vm7u4 / FIND-11).
- `docs/CONFORMANCE_HARNESS_MANIFEST.md` — top-level manifest
  declaring the 0.95 conformance-score budget.
