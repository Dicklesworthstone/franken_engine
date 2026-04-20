# External Evaluation Framework

## Red-team methodology

- **Threat model**: evaluate adversarial extension code, untrusted package inputs, and protocol abuse paths.
- **Attack classes**:
  - Prompt-injection and API surface abuse.
  - Type-confusion and bytecode-level manipulation attempts.
  - Resource-exhaustion via crafted workloads and dependency bombs.
  - Supply-chain tampering and metadata forgery in artifact manifests.
- **Process**:
  - Build a threat matrix with severity and reproducible exploit templates.
  - Run targeted generators for each class and capture pass/fail, traceback, and confinement counters.
  - Require containment under policy thresholds before any artifact is marked green.
  - Re-test historical regressions once per major commit.
- **Evidence artifacts**: each red-team run must emit execution trace ID, deterministic input seed, failure signature, and remediation verdict.

## Academic evaluation protocol

- **Hypotheses**: define explicit claims for correctness, security, and performance behavior under adversarial pressure.
- **Dataset design**: include
  - adversarial fixtures,
  - non-adversarial control fixtures,
  - and stress profiles with fixed seeds.
- **Protocol controls**:
  - lock commit hash, compiler version, and runtime flags;
  - pre-register inclusion/exclusion criteria;
  - use blinded evaluation scripts when comparing against baselines.
- **Analysis plan**: report central tendency and spread (mean/median/IQR), effect size, and failure taxonomy.
- **Review requirements**: independent reproduction or peer review must validate methodology and artifact integrity before publication.

## Published failures

- Maintain a machine-readable list of known failure classes and minimal reproducer references.
- For each published failure:
  - record severity, reproducibility, affected versions, and mitigation status;
  - keep remediation links and expected behavior after fix;
  - preserve raw logs and minimised inputs for future triage.
- New failures discovered during this cycle are added as entries and linked from the artifact registry for traceability.

## Replication Instructions

- **Prerequisites**: Record exact `git rev`, runtime, OS image, and compiler versions.
- **Reproducibility settings**: pin `CARGO_TARGET_DIR` and run with `CARGO_INCREMENTAL=0`.
- **Locking**: record exact `rustc`, dependency lockfile, and runtime environment; verify checkout is at the target commit.
- **Procedure**: Re-run the artifact generation and verification workflow from the same commit, capturing command output and logs.
- **Execution**:
  - run the red-team generators in deterministic mode;
  - execute the academic protocol script bundle end-to-end;
  - re-run controls and adversarial suites with matching seeds.
- **Verification**:
  - compare collected metrics to the published expected ranges;
  - confirm all required artifacts (traces, reports, and manifest hashes) exist.
- **Failure handling**: if outputs drift, capture provenance and mitigation notes before declaring success.
- **Artifact package**: store manifests, traces, scripts, and environment metadata under a versioned bundle path so others can replicate exactly.
