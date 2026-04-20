# Benchmark Reproducibility Audit

## Environment Pin Hash
- Record the exact CPU architecture, OS image, compiler version, and key dependency versions.
- Store immutable checksums/hashes for all pinned toolchain and benchmark inputs.
- Capture Docker/container image digests and host capability profiles.

## Workload Manifest
- Enumerate benchmark suites, iteration counts, warmup policy, and fixed seeds.
- Declare input corpora locations, revisions, and normalization steps.
- Track hardware affinity, memory ceilings, and runtime flags used during execution.

## Time Budget
- Define accepted wall-clock windows and variance thresholds for each benchmark target.
- Require explicit budget allocation per benchmark phase (setup, warmup, run, teardown).
- Record overruns and provide triage guidance for budget violations.

## Peer Replication Logs
- Store invocation logs and reproducibility notes from independent operators.
- Collect cross-machine deltas in result curves and environment drift reports.
- Keep a minimal protocol for failed replications and required remediation evidence.

## Audit Trail
- Track every audit pass with status, approver, timestamp, and verification artifacts.
- Preserve hash chains linking logs, result manifests, and artifact attachments.
- Emit a final reproducibility verdict with scope, limitations, and required follow-ups.

## Replication Instructions

- **Prerequisites**: Record exact `git rev`, runtime, OS image, and compiler versions.
- **Reproducibility settings**: pin `CARGO_TARGET_DIR` and run with `CARGO_INCREMENTAL=0`.
- **Procedure**: Re-run the artifact generation and verification workflow from the same commit, capturing command output and logs.
- **Validation**: Compare generated artifacts to listed expectations and note environment drift with mitigation notes.
