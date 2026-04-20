# FrankenEngine Compatibility Advisory Report

## Status

- **Report ID:** `FKTR-2026-003`
- **Status:** Draft skeleton
- **Owner:** FrankenEngine Research Team
- **Primary bead:** `bd-2501`
- **Advisory class:** Compatibility semantics and regression evidence

## Purpose

This report captures compatibility advisories where FrankenEngine behavior diverges
from established JavaScript runtime semantics, conformance expectations, or
documented extension-runtime compatibility contracts.

The report is intentionally scoped as an advisory artifact, not a closure claim:
each finding must link to a reproducible regression, a corrected implementation
bead, and an operator-readable compatibility note before it can be promoted to a
publishable technical report.

## Advisory Record Schema

Each advisory entry should include:

- **Advisory ID:** Stable identifier such as `FE-COMPAT-YYYY-NNN`.
- **Affected surface:** Runtime module, builtin, CLI, or compatibility gate.
- **Observed divergence:** The incorrect behavior in concrete terms.
- **Expected semantics:** The normative or project-contract behavior.
- **Regression fixture:** Test name, corpus input, or replay artifact.
- **Fix bead:** Bead tracking the implementation correction.
- **Verification command:** Focused command and target directory used for proof.
- **Residual risk:** Known limitations, waivers, or follow-up beads.

## Initial Advisory Backlog

| Advisory ID | Affected Surface | Expected Semantics | Tracking Bead | Status |
| --- | --- | --- | --- | --- |
| `FE-COMPAT-2026-001` | `String.prototype.split` omitted separator | `split()` and `split(undefined)` return `[original_string]`; `split("")` splits characters | `bd-2qzil` | Open |

## Promotion Criteria

This advisory report can only move from draft skeleton to publishable artifact
when all of the following are true:

1. Every listed advisory has a focused regression test.
2. Each fix bead is closed with a code commit and validation record.
3. The report links to reproducible artifacts or deterministic command output.
4. Residual compatibility waivers are explicit and time-bound.
5. The technical reports registry marks this report as reproducible.

## Operator Verification

For each advisory, operators should run the focused validation command listed in
the advisory record using an isolated target directory and `CARGO_INCREMENTAL=0`.
The command output should be attached to the relevant bead or artifact bundle
before any public compatibility claim is made.

## Replication Instructions

- **Prerequisites**: Record exact `git rev`, runtime, OS image, and compiler versions.
- **Reproducibility settings**: pin `CARGO_TARGET_DIR` and run with `CARGO_INCREMENTAL=0`.
- **Procedure**: Re-run the artifact generation and verification workflow from the same commit, capturing command output and logs.
- **Validation**: Compare generated artifacts to listed expectations and note environment drift with mitigation notes.
