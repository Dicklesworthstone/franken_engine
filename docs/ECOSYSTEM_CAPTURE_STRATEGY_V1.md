# Ecosystem Capture Strategy V1

## Purpose

`bd-3bz4` is the Section 15 strategy bead that turns FrankenEngine's technical
advantages into adoption-ready ecosystem surfaces. This document makes the bead
self-contained by mapping each execution pillar to the concrete delivery beads
that now satisfy it, the adoption targets those pillars enable, and the
remaining parent-epic context that still lives outside this bead.

The strategy is considered complete only when:

1. every execution pillar listed below is backed by closed delivery beads,
2. every adoption target has a closed evidence-producing delivery bead, and
3. every upstream prerequisite needed to trust the adoption claims is closed.

As of 2026-03-21, all Section 15 execution pillars and this bead's declared
upstream prerequisites are closed. That means `bd-3bz4` can close once its
status bundle and replayable verification surface exist.

## Execution Pillars

### 1. Signed extension registry

- Strategy intent: make FrankenEngine the default home for high-trust extension
  publishing and revocation.
- Delivery beads:
  - `bd-3bz4.1`
  - `bd-mrf8`
- User outcome: operators can publish, verify, and revoke signed extensions
  with provenance and revocation evidence instead of relying on implicit trust.

### 2. Node/Bun migration validation

- Strategy intent: convert incumbent Node/Bun workflows into deterministic,
  capability-typed FrankenEngine workflows without hand-waving over behavior
  changes.
- Delivery beads:
  - `bd-3bz4.2`
  - `bd-iqrn`
  - `bd-2wft`
- User outcome: migration paths are artifact-backed, behavior-validated, and
  suitable for both one-off migrations and repeatable cohort rollouts.

### 3. Enterprise governance hooks

- Strategy intent: give enterprises policy-as-code, audit export, and
  compliance evidence surfaces that make FrankenEngine operable in regulated
  environments.
- Delivery beads:
  - `bd-3bz4.3`
  - `bd-2r0c`
- User outcome: governance controls are integrated into CI/CD and audit flows
  rather than treated as manual afterthoughts.

### 4. Reputation graph APIs

- Strategy intent: let ecosystem trust and incident knowledge propagate across
  organizations and deployments with explainable trust-card outputs.
- Delivery bead:
  - `bd-2x4b`
- User outcome: operators can consume ecosystem trust signals and rapid incident
  response data through explicit APIs.

### 5. Partner program and proof points

- Strategy intent: turn the ecosystem strategy into externally legible adoption
  proof rather than internal ambition.
- Delivery beads:
  - `bd-1wqa`
  - `bd-3j5s`
- User outcome: early lighthouse adopters and public case studies provide
  adoption evidence that can be inspected by downstream partners and Section 16
  research/reporting work.

## Adoption Targets

### Greenfield onboarding

- Delivery bead: `bd-3qhv`
- Outcome: a new user can start from a minimal-friction deterministic safe
  extension workflow instead of assembling the stack by hand.

### Migration validation

- Delivery bead: `bd-2wft`
- Outcome: representative Node/Bun extension packs have deterministic behavior
  validation artifacts proving the migration path is real.

### Public case studies

- Delivery bead: `bd-3j5s`
- Outcome: materially improved security and operational outcomes are documented
  in a form suitable for external review.

## Upstream Prerequisites

The Section 15 strategy only makes credible adoption claims when the following
technical prerequisites are closed:

- `bd-uvmm`: canonical evidence entries via `franken-evidence`
- `bd-3a5e`: high-impact safety actions routed through
  `franken-decision`
- `bd-1bzp`: category benchmark specification
- `bd-2vu`: differential Node/Bun lockstep suite
- `bd-3gsv`: third-party verifier toolkit
- `bd-3ovc`: low-latency reputation updates and explainable trust cards
- `bd-39f0`: secure extension reputation graph schema
- `bd-26o`: serialization, signature, revocation, and epoch conformance suite

The strategy bundle fails closed if any of those prerequisites are no longer
closed, because the ecosystem capture story would then drift away from the
technical evidence it depends on.

## Closure Semantics

Closing `bd-3bz4` means:

- Section 15's strategy bead is fully backed by closed delivery beads,
- the ecosystem capture pillars are no longer a planning-only promise, and
- the parent Section 15 execution epic `bd-1jak` can treat this strategy bead as
  satisfied.

Closing `bd-3bz4` does not imply that every Section 15 or parent-program bead is
closed. `bd-1jak` still tracks additional Section 15 deliverables plus its own
Section 13, Section 14, and master-program blockers.

## Bundle Artifacts

The validation bundle produced by the runner lives under:

`artifacts/ecosystem_capture_strategy/<UTC_TIMESTAMP>/`

Required artifacts:

- `run_manifest.json`
- `events.jsonl`
- `commands.txt`
- `trace_ids.json`
- `milestone_status_report.json`
- `blocker_status_report.json`
- `strategy_summary.md`
- `ecosystem_capture_strategy_v1.json`
- `ecosystem_capture_strategy_v1.md`
- `step_logs/step_*.log`

## Operator Verification

```bash
jq empty docs/ecosystem_capture_strategy_v1.json
rch exec -- env RUSTUP_TOOLCHAIN=nightly CARGO_TARGET_DIR=$PWD/target_rch_ecosystem_capture_strategy_verify CARGO_BUILD_JOBS=1 CARGO_INCREMENTAL=0 cargo test -p frankenengine-engine --test ecosystem_capture_strategy
./scripts/run_ecosystem_capture_strategy.sh ci
./scripts/e2e/ecosystem_capture_strategy_replay.sh show
```
