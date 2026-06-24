# Semantic Fidelity Frontier Ingest Runbook

Status: scoped runbook for `bd-09bea.5`
Contract: `docs/SEMANTIC_FIDELITY_FRONTIER_INGEST_CONTRACT.md`
Transformer: `scripts/semantic_fidelity_frontier_ingest.py`
Report: `scripts/semantic_fidelity_frontier_report.py`
Smoke gate: `scripts/e2e/semantic_fidelity_frontier_ingest_smoke.sh`

## When To Use This Bridge

Use this bridge when a semantic-fidelity workbench bundle already exists and an
operator needs an E7-shaped subset report before full E2/Test262 inputs are
available. The current seed bundle is:

```text
artifacts/semantic_fidelity_workbench_gate/bd-mihky-10-capstone-20300101T000000Z
```

The bridge is useful for:

- preserving `bd-mihky` vector provenance in an E7-friendly shape
- grouping workbench rows by stable content-derived cluster ids
- surfacing source-eval expected-unknown rows as non-passing scoped evidence
- giving E7 consumers a replayable subset artifact without unblocking or
  replacing `bd-fqlfw.7.1`

## What This Bridge Does Not Prove

This bridge does not prove full JavaScript conformance, Test262 coverage, or
Node/Bun denominator readiness. It must not update README wording or
claim-to-proof matrix rows. The emitted scope is always
`semantic_fidelity_subset`, and the claim policy is always
`no_claim_promotion`.

Rows counted as `accepted_external_oracle` are eligible only inside this subset
report. Rows in `declared_non_execution`, `expected_unknown`, `unsupported`,
`degraded`, `mismatch`, or `malformed` state cannot be counted as passing
coverage.

## Commands

Generate a frontier ingest bundle:

```bash
scripts/semantic_fidelity_frontier_ingest.py \
  --bundle artifacts/semantic_fidelity_workbench_gate/bd-mihky-10-capstone-20300101T000000Z \
  --out /tmp/semantic_fidelity_frontier_ingest.json \
  --pretty
```

Render the scoped report:

```bash
scripts/semantic_fidelity_frontier_report.py \
  --ingest /tmp/semantic_fidelity_frontier_ingest.json \
  --out /tmp/semantic_fidelity_frontier_report.md
```

Run the build-free smoke gate:

```bash
scripts/e2e/semantic_fidelity_frontier_ingest_smoke.sh /tmp/semantic_fidelity_frontier_smoke
```

The smoke gate validates:

- fixture transform and stable cluster summary
- expected report rendering
- explicit zero-count rows for mismatch, unsupported, expected_unknown,
  malformed, and degraded states
- missing workbench bundle fail-closed diagnostics
- missing report-input fail-closed diagnostics

## RCH Policy

The bridge scripts are Python and shell only. The current gate does not invoke
Cargo, Rust tests, clippy, or builds. If future bridge work touches Rust sources
or runs any Cargo-heavy validation, run it through `rch` with remote-only
settings.

## Handoff To E7

Use this bridge output as fixture evidence for E7 discussion and report
plumbing. Full `coverage_frontier` work remains under `bd-fqlfw.7.1` and still
requires E2/Test262 oracle inputs. Do not wire automatic bead filing from this
subset unless it goes through the E7 dedup and human-review path.

Recommended related beads for reports:

- `bd-mihky`
- `bd-mihky.10`
- `bd-fqlfw.7`
- `bd-xulus`
