# Reproducibility Scorecard

## Artifact Bundle Contents

- Source snapshot identifier (commit SHA) and provenance metadata.
- Exact command and script set used to generate each artifact.
- Deterministic inputs (fixtures, seeds, corpus revision identifiers).
- Environment and toolchain manifest.
- Raw logs, result tables, and hash manifests for each generated output.

## Environment Pin

- `rustc` toolchain version.
- LLVM/target triple and CPU feature flags used for native artifacts.
- Dependency lockfile hash (`Cargo.lock`) and external dataset versions.
- Operating system details and container/VM metadata.
- Timezone, locale, and entropy source settings.

## Replay Seed

- Record per-suite seed values and seed derivation logic.
- Include any seed-rotation or sharding parameters.
- Preserve seed-to-artifact mappings for each run.
- Keep seed manifests immutable and checksummed for replay.

## Expected Output Hash

- Store deterministic hash digests (SHA-256) for each critical output.
- Include manifest hashes for intermediate stages and final artifacts.
- Fail closed when any digest mismatch is detected.
- Keep prior-run hashes available for regression diffing.

## Scorecard Thresholds

- Minimum passing criteria for replication: exact artifact hashes, zero hard failures, expected control-vs-treatment deltas, and acceptance of all required log lines.
- Alert thresholds for soft failures (warn), hard thresholds for hard fails (fail build).
- Define deterministic rerun policy for hash or environment drift.
- Require sign-off only after all thresholds remain within bounds over repeated replay.
