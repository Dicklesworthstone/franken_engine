# Adding a New Capability to an Extension Manifest

This workflow shows an extension author how to respond to a
`LoweringPipelineError::AmbientAuthorityViolation` diagnostic from the
[Capability-Typed Compile-Time Rejection Gate](./RGC_GATES_REFERENCE.md#capability-typed-compile-time-rejection-gate),
extend the extension's capability manifest, and rerun the gate to
confirm the rejection has cleared.

It assumes:

- The rejected call site is a legitimate use the extension intends to
  make. If the diagnostic's `evasion_class` looks like one of the
  catalogued laundering patterns under
  [`crates/franken-engine/tests/red_team_scenarios/`](../../crates/franken-engine/tests/red_team_scenarios/),
  use the *Bug or laundering attempt* path in `RGC_GATES_REFERENCE.md`
  instead — do **not** widen the manifest to silence a laundering
  diagnostic.
- The deployment lane's security review allows the capability. Each
  `EffectKind` has a row in
  [`docs/CLAIM_TO_PROOF_MATRIX_V1.md`](../CLAIM_TO_PROOF_MATRIX_V1.md);
  surfaces in `HYPOTHESIS` state are not yet approved for production
  deployment.

## Bead anchor

- `bd-cixqu.3` (FE-CLAIM-006, Track C) — parent track.
- `bd-cixqu.3.7` (C.7 operator-runbook) — this document is part of the
  operator-runbook acceptance for that bead.

## Prerequisites

- `frankenctl` built from this workspace (see
  [README "Build From Source"](../../README.md#build-from-source-quick-start)).
- The extension's source under `extensions/<name>/`.
- The extension's capability manifest at
  `extensions/<name>/extension.capability.manifest.json` (create one if
  the extension does not yet have one — the gate refuses extensions
  without a manifest).
- A clean working tree (so the diff after the workflow is
  understandable).

## Step 1 — Capture the rejection diagnostic

Run the gate against the extension under audit:

```bash
./scripts/run_rgc_capability_typed_compile_time.sh \
    --extension extensions/<name> \
    ci
```

When the gate refuses a call site it emits a
`capability_rejection_report.json` under
`artifacts/rgc_capability_typed_compile_time/<timestamp>/`. Open it.
Each rejection record carries:

| Field | Meaning |
|---|---|
| `source_span` | Path, line, column of the rejected call site. |
| `required_capability` | The `EffectKind` (e.g. `fs.read`, `net.connect`) the call site would need granted. |
| `calling_scope_effects` | The resolved `EffectSet` the calling scope declared (empty if no opt-in). |
| `evasion_class` | Named pattern if the rejection matches a catalogued evasion. **If non-null, stop and use the *Bug or laundering attempt* path.** |
| `chain_root` | Original Node module the binding chain resolves to (for transitive re-exports). |
| `claim_id` | `bd-cixqu.3` — traces the diagnostic back to the FE-CLAIM-006 contract. |

If the `evasion_class` is **null**, the rejection is a normal under-declared
capability and this workflow applies.

## Step 2 — Confirm the EffectKind is approved for your lane

Open [`docs/CLAIM_TO_PROOF_MATRIX_V1.md`](../CLAIM_TO_PROOF_MATRIX_V1.md)
and find the row whose claim id matches the `required_capability` value
(for example, `fs.read` → look for the row whose state column covers
`fs.read`).

| State | Action |
|---|---|
| `OBSERVED` | Safe to declare in your extension manifest. Proceed to Step 3. |
| `TARGETED` | The capability is a design goal but not yet artifact-backed. Talk to your security reviewer before declaring; you may be asked to wait for the row to promote. |
| `HYPOTHESIS` | Not yet shipped. Do **not** declare. Either change the extension to avoid the surface or file a bead to promote the capability. |

## Step 3 — Edit the extension capability manifest

Open `extensions/<name>/extension.capability.manifest.json`. The
manifest is canonically a JSON object whose top-level fields are at
least:

```jsonc
{
  "schema_version": "franken-engine.extension-capability-manifest.v1",
  "extension_name": "<name>",
  "declared_effects": [
    // entries here are EffectKind values from
    // crates/franken-engine/src/effect_set.rs::EffectKind::as_str()
  ],
  "policy": "declared"
}
```

Add the `required_capability` from Step 1 to `declared_effects`. The
order does not matter for correctness, but keep the list alphabetically
sorted so manifest diffs are reviewable. Example, before:

```json
"declared_effects": ["clock.read", "policy.request"]
```

after adding `fs.read`:

```json
"declared_effects": ["clock.read", "fs.read", "policy.request"]
```

If the extension does not yet have an explicit `policy` field, add
`"policy": "declared"`. The three valid policies are:

| Policy | Meaning |
|---|---|
| `empty` | Implicit opt-out from every capability. The default; do not write it. |
| `inherited` | Closure-only: this manifest scope inherits its calling scope's set. Not valid for top-level extension manifests. |
| `declared` | This manifest explicitly enumerates the capabilities the extension may reach. The required setting for extensions. |

## Step 4 — Regenerate the typed-effect inventory

Run the gate again with the updated manifest:

```bash
./scripts/run_rgc_capability_typed_compile_time.sh \
    --extension extensions/<name> \
    ci
```

Inspect the new `effect_annotation_inventory.json`. Confirm:

- Every function/method node in your extension has an `EffectAnnotation`
  whose `policy` field is `"declared"`.
- The `effects` set on the entry-point function includes the
  `EffectKind` you added.
- No new rejections appear in
  `capability_rejection_report.json` — if any do, repeat Step 1 for
  each.

## Step 5 — Replay verification

Run the gate's replay wrapper to confirm the run is reproducible:

```bash
./scripts/e2e/rgc_capability_typed_compile_time_replay.sh \
    --extension extensions/<name> \
    ci
```

The replay regenerates the bundle from the captured `commands.txt` and
diffs it against the original. A clean replay is the signal that the
manifest edit is determinism-clean (no side effects from build
ordering or environment).

## Step 6 — Commit and ship

```bash
git add extensions/<name>/extension.capability.manifest.json
git commit -m "feat(<name>): declare <effect-kind> capability (bd-cixqu.3.7 workflow)"
```

If the deployment lane requires a security review for capability
widening, attach the
`artifacts/rgc_capability_typed_compile_time/<timestamp>/run_manifest.json`
to the review request. The manifest's content hash is the bundle's
identity.

## When to escalate to a security review

This workflow assumes a legitimate use case. Escalate instead of editing
the manifest when **any** of the following is true:

- The diagnostic's `evasion_class` is non-null. Catalogued evasion
  classes are by definition not legitimate uses; widening the manifest
  to silence one is a regression in security posture.
- The diagnostic's `chain_root` is `child_process`, `fs/promises`, or
  any Node module whose surface the deployment lane has not approved
  for the extension.
- The `required_capability` is `runtime.eval` or `runtime.global` —
  these surfaces are reserved for runtime-internal scopes and not
  available to extension manifests in any current deployment lane.
- The `EffectKind`'s row in the claim-to-proof matrix is
  `HYPOTHESIS` — declaring an unshipped capability is a no-op in this
  release but may lock in a misleading manifest for the next.

A clear diagnostic with a clear fix is the goal. If you reach this
workflow and the diagnostic is unclear, file a bead naming the gate
run's `trace_ids.json` so the diagnostic itself can be improved — that
keeps the gate adoptable.
