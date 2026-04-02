# Scientific Report Catalog V1

## Purpose

`bd-2501.1` requires at least four publishable technical reports with
reproducible artifact bundles. This catalog makes the candidate report lanes,
their evidence surfaces, and their current blocker state machine-checkable.

The catalog is intentionally conservative:

- a report lane is only considered publication-ready when its status bead is
  closed,
- every required supporting bead is closed,
- the primary operator-facing document exists, and
- reproducibility and replay commands are explicitly declared.

This catalog does not claim that all four reports are already publishable.
It exists to turn the milestone into an auditable closure surface.

## Report Lanes

### 1. Probabilistic Guardplane and Observability-On Publication Policy

- Status bead: `bd-1lsy.11.20.3`
- Primary doc: `docs/RGC_OBSERVABILITY_PUBLICATION_POLICY_V1.md`
- Artifact root: `artifacts/rgc_observability_publication_policy/<timestamp>/`
- Research angle: publication-grade observability governance, calibration
  sentinels, and fail-closed claim suppression.

### 2. Security Enforcement Verification Pack

- Status bead: `bd-1lsy.11.9`
- Primary doc: `docs/RGC_SECURITY_ENFORCEMENT_VERIFICATION_PACK_V1.md`
- Artifact root:
  `artifacts/rgc_security_enforcement_verification_pack/<timestamp>/`
- Research angle: adversarial capability, IFC, and containment evaluation with
  replay-linked evidence.

### 3. Runtime Semantics Verification Pack

- Status bead: `bd-1lsy.11.7`
- Primary doc: `docs/RGC_RUNTIME_SEMANTICS_VERIFICATION_PACK_V1.md`
- Artifact root:
  `artifacts/rgc_runtime_semantics_verification_pack/<timestamp>/`
- Research angle: deterministic runtime-semantics evidence spanning unit,
  integration, and end-to-end replayable scenarios.

### 4. Extension-Heavy Benchmark Methodology and Peer Comparison

- Status bead: `bd-19l0`
- Supporting bead: `bd-1ze`
- Primary doc: `docs/EXTENSION_HEAVY_BENCHMARK_SUITE_V1.md`
- Artifact root: `artifacts/benchmarks/<timestamp>/`
- Research angle: neutral benchmark methodology, reproducibility contract, and
  publishable Node/Bun comparison posture.

## Closure Semantics

`bd-2501.1` is ready to close only when:

1. the catalog still contains at least four report lanes,
2. every report lane is marked publication-ready in
   `technical_report_status_report.json`,
3. the corresponding artifact-bundle surfaces remain declared and reproducible,
   and
4. the milestone bead itself is closed with linked verification evidence.
