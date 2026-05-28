# Conformance Waivers — Operator Guide

> Bead: [bd-r2vw9](https://) (FIND-19) / parent
> [bd-85qfs](https://) — Conformance test harness audit (ScarletJay,
> 2026-05-28). This guide covers the two waiver registries that the
> conformance release gates consume.

## What a waiver is

A waiver is an *expiring*, *attributed* exemption that lets a single
non-passing conformance case keep the green CI gate green while a real
fix is in flight. Waivers are NOT permanent allowlists — every waiver
must cite a tracking bead, an expiry date, and a reviewer; the gate
fails closed if a waiver expires without being lifted or renewed.

The waiver system exists so a brand-new audit finding (e.g., one of the
FIND-N beads filed under [bd-85qfs](https://) on 2026-05-28) can land
its case wire-up without immediately turning CI red, while the engine
work is tracked separately.

## Registries

There are two registries in this tree, owned by different gates.
**Keep them in sync schema-wise but separate operationally**: a
test262 waiver only applies to a test262 case; a transplanted
conformance-asset waiver only applies to a `tests/conformance/transplanted/`
asset. There is no shared identifier across the two.

### `test262_conformance_waivers.toml`

Loaded by `tests/test262_release_gate.rs::load_waivers` via
`Test262WaiverSet::load_toml(...)`. Schema version
`franken-engine.test262-waiver.v1`.

Each `[[waiver]]` entry MUST set:

| Field           | Type / Format                                | Notes                                                       |
|-----------------|----------------------------------------------|-------------------------------------------------------------|
| `test_id`       | upstream test262 case path (string)          | e.g. `language/expressions/optional-chaining/short-circuiting.js` |
| `reason_code`   | enum (`Test262WaiverReason`)                 | e.g. `not_yet_implemented`, `host_hook_missing`             |
| `es2020_clause` | ECMA-262 §N.N.N (string)                     | The clause the case asserts; lets graders correlate         |
| `tracking_bead` | `bd-…` ID                                    | Pointer to the bead that drops the waiver                   |
| `expiry_date`   | YYYY-MM-DD                                   | Hard expiry; gate fails closed when reached                 |
| `reviewer`      | team / role string                           | e.g. `runtime-conformance`                                  |

Example:

```toml
schema_version = "franken-engine.test262-waiver.v1"

[[waiver]]
test_id        = "language/expressions/optional-chaining/short-circuiting.js"
reason_code    = "not_yet_implemented"
es2020_clause  = "13.3.1"
tracking_bead  = "bd-11p"
expiry_date    = "2030-12-31"
reviewer       = "runtime-conformance"
```

### `conformance_waivers.toml`

Loaded by `tests/conformance_assets.rs` via
`ConformanceWaiverSet::load_toml(...)` (also used by
`test_conformance_gate_pipeline_smoke` and the per-asset drivers).
Covers the *transplanted* corpus and any other harness that surfaces
asset IDs (not test262 case paths).

Each `[[waiver]]` entry MUST set:

| Field           | Type / Format                                | Notes                                                       |
|-----------------|----------------------------------------------|-------------------------------------------------------------|
| `asset_id`      | conformance-asset ID (string)                | e.g. `asset-example-not-yet-implemented`                    |
| `reason_code`   | enum                                         | Same enum surface as the test262 registry                   |
| `tracking_bead` | `bd-…` ID                                    | Required                                                    |
| `expiry_date`   | YYYY-MM-DD                                   | Required                                                    |

## When to add a waiver

Add a waiver when ALL of the following are true:

1. **A real fix is filed** (with a tracking bead) and someone is on
   the hook for it.
2. **The case otherwise blocks CI** and there is no equivalent
   coverage already in place.
3. **The expiry date is realistic** — pick the soonest date by which
   the tracking bead is expected to land. Default to ≤ 12 months;
   longer expiries require an explicit reviewer line attesting why.

Do NOT add a waiver to silence a flaky test, hide a regression, or
move a still-relevant assertion out of the way.

## When to remove a waiver

Remove a waiver when ANY of the following are true:

1. **The tracking bead is closed and the case now passes** — the
   waiver line is dead weight and a misleading audit trail.
2. **The expiry date has passed and no extension was authorised** —
   the gate is already failing; the right move is to fix the case or
   re-justify the waiver, not to bump the date silently.
3. **The case itself is removed** (upstream test262 deletion, asset
   pruned) — orphan waivers must be cleaned up so future grep-ability
   of `test_id`/`asset_id` strings stays honest.

## Renewal checklist

Bumping `expiry_date` on an existing waiver is allowed only if:

- A reviewer comment is added to the waiver's tracking bead naming
  the new date and the concrete reason the original date slipped.
- The new `expiry_date` is ≤ 6 months from today.
- The reviewer field is updated if a different person/team is now
  on the hook.

If those conditions aren't met, the waiver should be removed and the
case fixed.

## Reason-code vocabulary

Both registries draw from a small, audited reason-code enum (see
`Test262WaiverReason` in the engine for the canonical list). Adding a
new reason code is itself a bead — don't free-text new strings.

The codes that exist today include:

| Code                    | Meaning                                                              |
|-------------------------|----------------------------------------------------------------------|
| `not_yet_implemented`   | Engine doesn't implement this language feature yet                   |
| `host_hook_missing`     | Engine implements the case but the host integration is missing      |
| `intentional_divergence`| Engine intentionally differs from the spec; cross-reference DISCREPANCIES |
| (future codes)          | Added as bd-?? beads land — keep this table in sync                  |

## Audit cadence

The whole registry should be skimmed during every conformance audit
(currently quarterly per [bd-rpimp](https://) — see
`TEST262_REFRESH_POLICY.md`). The auditor checks:

1. Every `tracking_bead` resolves to a real, still-open bead.
2. Every `expiry_date` is in the future (or being renewed in flight).
3. No two waivers cover the same `test_id` / `asset_id`.
4. The cumulative waiver count is trending down, not up.

## Related Docs

- `tests/conformance/PROVENANCE.md` — the corpora the waivers cover.
- `TEST262_REFRESH_POLICY.md` — fixture refresh cadence
  (bd-rpimp / FIND-23).
- `CONFORMANCE_GOLDENS_REGEN.md` — UPDATE_GOLDENS path for the
  conformance harnesses (bd-vm7u4 / FIND-11).
- A future top-level ES2020 `DISCREPANCIES.md`
  (bd-w50mz / FIND-4) will own the **permanent** intentional
  divergences; waivers cover only the *temporary* exemptions.
