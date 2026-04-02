# External Replication Catalog V1

## Purpose

`bd-2501.2` requires at least two externally replicated high-impact claims.
This catalog makes the candidate claim lanes, their verifier surfaces, and
their current blocker state machine-checkable.

The catalog is intentionally conservative:

- a claim lane is only considered verifier-ready when its implementation status
  bead is closed,
- every required supporting bead is closed,
- both the primary claim document and verifier-facing document exist, and
- reproducibility and replay commands are explicitly declared.

This catalog does not claim that two claims are already externally replicated.
It exists to turn replication readiness into an auditable closure surface while
the milestone itself remains fail-closed.

## Claim Lanes

### 1. Extension-Heavy Benchmark Peer Claim Bundle

- Status bead: `bd-19l0`
- Supporting beads: `bd-1ze`, `bd-3gsv`
- Primary doc: `docs/EXTENSION_HEAVY_BENCHMARK_SUITE_V1.md`
- Verifier doc: `docs/THIRD_PARTY_VERIFIER_TOOLKIT.md`
- Artifact root: `artifacts/benchmarks/<timestamp>/`
- Research angle: independent rerun of Node/Bun benchmark claims through a
  neutral verifier workflow instead of project-private score assertions.

### 2. Security Enforcement Independent Verification Bundle

- Status bead: `bd-1lsy.11.9`
- Supporting beads: `bd-3gsv`, `bd-3rd`
- Primary doc: `docs/RGC_SECURITY_ENFORCEMENT_VERIFICATION_PACK_V1.md`
- Verifier doc: `docs/THIRD_PARTY_VERIFIER_TOOLKIT.md`
- Artifact root:
  `artifacts/rgc_security_enforcement_verification_pack/<timestamp>/`
- Research angle: containment, capability, and IFC claims become externally
  rerunnable through verifier-facing artifacts and fail-closed checks.

### 3. Runtime Replay and Receipt Verification Bundle

- Status bead: `bd-1lsy.11.7`
- Supporting beads: `bd-3gsv`, `bd-3ab3`
- Primary doc: `docs/RGC_RUNTIME_SEMANTICS_VERIFICATION_PACK_V1.md`
- Verifier doc: `docs/THIRD_PARTY_VERIFIER_TOOLKIT.md`
- Artifact root: `artifacts/rgc_runtime_semantics_verification_pack/<timestamp>/`
- Research angle: deterministic replay and receipt-linked runtime claims can be
  independently rerun without insider-only infrastructure.

## Closure Semantics

`bd-2501.2` is ready to close only when:

1. the catalog still contains at least two claim lanes,
2. at least two claim lanes are marked verifier-ready in
   `external_replication_status_report.json`,
3. independent external reruns are recorded through milestone-bead evidence
   rather than internal assertions, and
4. the milestone bead itself is closed with linked verification evidence.
