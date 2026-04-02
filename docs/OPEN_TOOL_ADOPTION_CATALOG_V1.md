# Open Tool Adoption Catalog V1

## Purpose

`bd-2501.3` requires at least one open benchmark or verification tool adopted
outside the project. This catalog makes candidate tool lanes, their release
surfaces, and their adoption-evidence gaps machine-checkable.

The catalog is intentionally conservative:

- a tool lane is only considered release-ready when its release bead is closed,
- every required supporting bead is closed,
- the primary operator-facing document exists, and
- reproducibility and replay commands are explicitly declared.

A tool lane is only considered externally adoption-ready when an explicit
adoption-evidence document exists in addition to the release-ready conditions.

## Tool Lanes

### 1. Third-Party Verifier Toolkit (`franken-verify`)

- Release bead: `bd-3gsv`
- Supporting bead: `bd-3ab3`
- Primary doc: `docs/THIRD_PARTY_VERIFIER_TOOLKIT.md`
- Artifact root: `artifacts/third_party_verifier/<timestamp>/`
- Adoption evidence doc:
  `docs/THIRD_PARTY_VERIFIER_TOOLKIT_ADOPTION_EVIDENCE_V1.md`
- External value: a verifier CLI that lets third parties audit benchmark,
  replay, containment, and attestation claims without the FrankenEngine control
  plane.

### 2. Extension-Heavy Benchmark Suite v1.0

- Release bead: `bd-19l0`
- Supporting bead: `bd-1ze`
- Primary doc: `docs/EXTENSION_HEAVY_BENCHMARK_SUITE_V1.md`
- Artifact root: `artifacts/benchmarks/<timestamp>/`
- Adoption evidence doc:
  `docs/EXTENSION_HEAVY_BENCHMARK_ADOPTION_EVIDENCE_V1.md`
- External value: a neutral, publishable benchmark methodology that other
  runtime teams can use to score their own systems.

### 3. Parser Third-Party Rerun Kit

- Release bead: `bd-2mds.1.7.4`
- Supporting bead: `bd-2mds.1.7.3`
- Primary doc: `docs/PARSER_THIRD_PARTY_RERUN_KIT.md`
- Artifact root: `artifacts/parser_third_party_rerun_kit/<timestamp>/`
- Adoption evidence doc:
  `docs/PARSER_THIRD_PARTY_RERUN_KIT_ADOPTION_EVIDENCE_V1.md`
- External value: a one-command rerun bundle that external operators can use to
  validate parser reproducibility claims without insider knowledge.

## Closure Semantics

`bd-2501.3` is ready to close only when:

1. the catalog still contains at least one candidate tool lane,
2. at least one tool lane is marked `ready_for_external_adoption` in
   `open_tool_adoption_status_report.json`,
3. the linked adoption evidence documents actual outside-project usage rather
   than internal dry runs, and
4. the milestone bead itself is closed with linked adoption evidence.
