# Real Hot Path Evidence Runbook

**Status:** Active
**Bead:** bd-t5k40.7
**Policy ID:** policy-real-hot-path-proof-v1

## Scope

This runbook covers the `real_runtime_hot_paths` proof lane. The lane provides
observed internal evidence that FrankenEngine hot-path workloads execute through
the real runtime benchmark harness, through `rch`, with deterministic proof
artifacts.

It does not prove Node/Bun denominator throughput claims. Keep `>= 3x`
throughput wording in the `target` state until fresh denominator artifacts are
available under the benchmark denominator contract. See
`docs/CLAIM_TO_PROOF_MATRIX_V1.md` for observed/target/hypothesis policy.

Related gate references:

- `docs/RGC_PERFORMANCE_REGRESSION_GATE_V1.md`
- `docs/RCH_VALIDATION_EVIDENCE_LEDGER_RUNBOOK.md`
- `docs/CLAIM_TO_PROOF_MATRIX_V1.md`

## Quick Start

Run the complete no-mock operator drill:

```bash
scripts/e2e/real_hot_path_evidence_drill.sh smoke
```

The drill runs `scripts/run_real_hot_path_proof.sh smoke`, validates the emitted
proof bundle with `scripts/real_hot_path_proof_contract_gate.sh`, records
artifact digests, extracts `rch` summary lines, and checks fail-closed negative
cases.

For explicit worker and target-dir policy, use:

```bash
REAL_HOT_PATH_EVIDENCE_DRILL_ARTIFACT_ROOT=artifacts/real_hot_path_evidence_drill \
RCH_DAEMON_WAIT_RESPONSE_TIMEOUT_SECS=3600 \
RCH_QUEUE_WHEN_BUSY=1 \
RCH_PRIORITY=high \
RCH_VISIBILITY=verbose \
RCH_TEST_TIMEOUT_SEC=1800 \
CARGO_TARGET_DIR=/tmp/rch_target_franken_engine_real_hot_path_evidence_drill \
CARGO_INCREMENTAL=0 \
CARGO_BUILD_JOBS=4 \
RUSTFLAGS=-Cdebuginfo=0 \
scripts/e2e/real_hot_path_evidence_drill.sh smoke
```

## Direct Proof Run

Use the direct wrapper when you only need a proof bundle and will run the
contract gate separately:

```bash
RCH_DAEMON_WAIT_RESPONSE_TIMEOUT_SECS=3600 \
RCH_QUEUE_WHEN_BUSY=1 \
RCH_PRIORITY=high \
RCH_VISIBILITY=verbose \
RCH_TEST_TIMEOUT_SEC=1800 \
CARGO_TARGET_DIR=/tmp/rch_target_franken_engine_real_hot_path_proof \
CARGO_INCREMENTAL=0 \
CARGO_BUILD_JOBS=4 \
RUSTFLAGS=-Cdebuginfo=0 \
scripts/run_real_hot_path_proof.sh smoke
```

The wrapper command routed through `rch` is:

```bash
cargo bench -p frankenengine-engine --no-default-features --bench hot_paths -- --test
```

Do not run that Cargo command directly. The wrapper records the exact `rch exec`
command in `commands.txt` and fails closed on local fallback, missing remote
exit markers, nonzero remote exits, or wrapper failure.

## Contract Gate

Validate a proof bundle:

```bash
bundle=artifacts/real_hot_path_proof/<timestamp>
source_revision="$(jq -r '.git_commit' "${bundle}/run_manifest.json")"

scripts/real_hot_path_proof_contract_gate.sh \
  --bundle-dir "$bundle" \
  --source-revision "$source_revision"
```

The gate exits:

- `0` for accepted proof evidence.
- `42` for contract failures that were readable enough to diagnose.
- `64` for invalid gate arguments.
- `2` for missing gate tools.

## Artifact Contract

The proof bundle must include:

- `run_manifest.json`: schema, mode, source revision, target-dir policy, command,
  `rch` worker, remote exit, proof outcome, and declared artifact paths.
- `trace_ids.json`: trace, decision, policy, and component identifiers.
- `events.jsonl`: at least one passing `real_hot_path_proof_completed` event with
  `runtime_lane=real_runtime_hot_paths`.
- `commands.txt`: exact `rch exec -- ... cargo bench ... --bench hot_paths`
  command.
- `step_logs/step_000_real_hot_path_proof.log`: wrapper step transcript.
- `rch-log.step_000.log`: selected-worker and remote-exit transcript.

The drill additionally writes:

- `summary.json`: compact operator summary, source revision, proof bundle,
  correctness digest, and negative case results.
- `summary.md`: replay summary for humans.
- `artifact_digests.json`: SHA-256 and byte size for every proof bundle file.
- `logs/rch_summary.log`: selected worker, remote exit, and `[RCH]` summary
  lines.
- `negative/*`: copied bundles mutated to prove fail-closed behavior.

## Failure Triage

Wrapper failures:

- `FE-REAL-HOT-PATH-PROOF-RCH-LOCAL-FALLBACK`: discard evidence. Re-run through
  `rch`; do not treat local fallback as observed proof.
- `FE-REAL-HOT-PATH-PROOF-MISSING-REMOTE-EXIT`: preserve the log and rerun after
  checking `rch` health. The proof did not record a remote exit marker.
- `FE-REAL-HOT-PATH-PROOF-REMOTE-FAIL`: inspect `rch-log.step_000.log` and the
  benchmark output. This is a remote command failure.
- `FE-REAL-HOT-PATH-PROOF-RCH-FAIL`: the wrapper failed even though a remote exit
  may be present. Preserve both stdout and stderr.

Contract gate failures:

- `FE-REAL-HOT-PATH-CONTRACT-MISSING-ARTIFACT`: regenerate or restore the full
  bundle. Do not publish partial evidence.
- `FE-REAL-HOT-PATH-CONTRACT-MALFORMED-MANIFEST`: regenerate through the wrapper;
  do not hand-edit the manifest.
- `FE-REAL-HOT-PATH-CONTRACT-STALE-SOURCE-REVISION`: rerun after source changes.
- `FE-REAL-HOT-PATH-CONTRACT-TARGET-DIR-POLICY`: use an off-repo `/tmp`
  `CARGO_TARGET_DIR`.
- `FE-REAL-HOT-PATH-CONTRACT-RCH-POLICY`: require queue-when-busy, no local
  fallback, remote exit `0`, and a named worker.
- `FE-REAL-HOT-PATH-CONTRACT-LOG-MISMATCH`: keep the original `rch` transcript.
- `FE-REAL-HOT-PATH-CONTRACT-TRACE-MISMATCH`: regenerate the manifest, trace ids,
  and events together.
- `FE-REAL-HOT-PATH-CONTRACT-SYNTHETIC-CONTAMINATION`: discard the bundle. Any
  `hot_paths_simulation` or `MockCertificate` marker is fixture-only evidence.

## Metric Caveats

Use this lane to prove execution provenance, not product throughput claims. The
stable proof fields are source revision, command provenance, selected worker,
target-dir policy, remote proof state, artifact presence, and correctness digest.
Criterion timing values are intentionally not frozen as golden evidence.

If an operator needs regression analysis, compare the stable proof contract
first, then use the performance-regression gate for timing interpretation. Do
not promote README or claim-matrix throughput language from this lane alone.

## Comparing Runs

Compare two accepted gate diagnostics:

```bash
old=artifacts/real_hot_path_proof_contract_gate/<old>/diagnostics.json
new=artifacts/real_hot_path_proof_contract_gate/<new>/diagnostics.json

jq -S '.contract' "$old" > /tmp/real_hot_path_old_contract.json
jq -S '.contract' "$new" > /tmp/real_hot_path_new_contract.json
diff -u /tmp/real_hot_path_old_contract.json /tmp/real_hot_path_new_contract.json
```

Compare drill summaries:

```bash
jq -S '{source_revision, proof_bundle, contract_gate, negative_cases}' \
  artifacts/real_hot_path_evidence_drill/<old>/summary.json \
  > /tmp/real_hot_path_old_summary.json
jq -S '{source_revision, proof_bundle, contract_gate, negative_cases}' \
  artifacts/real_hot_path_evidence_drill/<new>/summary.json \
  > /tmp/real_hot_path_new_summary.json
diff -u /tmp/real_hot_path_old_summary.json /tmp/real_hot_path_new_summary.json
```

Expected digest drift is normal when source revision, command, worker, target
dir, or artifact paths change. Unexpected drift within the same source revision
requires preserving both bundles and checking the command and event artifacts.

## Acceptance Checklist

- bd-t5k40.3 wrapper: `scripts/run_real_hot_path_proof.sh smoke` emits
  `run_manifest.json`, `trace_ids.json`, `events.jsonl`, `commands.txt`, step
  logs, and `rch-log.step_000.log`.
- bd-t5k40.4 contract: `scripts/real_hot_path_proof_contract_gate.sh` validates
  the stable schema, command provenance, worker proof, target-dir policy,
  correctness digest, and failure diagnostics.
- bd-t5k40.4 goldens: `scripts/e2e/real_hot_path_proof_contract_gate_smoke.sh`
  covers valid, malformed manifest, missing artifact, and stale source cases.
- bd-t5k40.5 claim safety: `scripts/run_claim_to_proof_matrix_gate.sh` rejects
  simulated hot-path artifacts for observed performance claims.
- bd-t5k40.6 no-mock drill:
  `scripts/e2e/real_hot_path_evidence_drill.sh smoke` runs the real proof lane,
  records logs/digests/summaries, and proves missing worker proof, malformed
  output, stale source, and synthetic contamination fail closed.
- bd-t5k40.7 operator runbook: this document gives the exact command shapes,
  artifact paths, failure diagnostics, metric caveats, comparison workflow, and
  acceptance mapping.

## Validation Commands

```bash
bash -n scripts/run_real_hot_path_proof.sh
bash -n scripts/real_hot_path_proof_contract_gate.sh
bash -n scripts/e2e/real_hot_path_proof_contract_gate_smoke.sh
bash -n scripts/e2e/real_hot_path_evidence_drill.sh
shellcheck scripts/run_real_hot_path_proof.sh
shellcheck scripts/real_hot_path_proof_contract_gate.sh
shellcheck scripts/e2e/real_hot_path_proof_contract_gate_smoke.sh
shellcheck scripts/e2e/real_hot_path_evidence_drill.sh
scripts/e2e/real_hot_path_proof_contract_gate_smoke.sh
scripts/e2e/real_hot_path_evidence_drill.sh smoke
git diff --check -- docs/REAL_HOT_PATH_EVIDENCE_RUNBOOK.md \
  scripts/run_real_hot_path_proof.sh \
  scripts/real_hot_path_proof_contract_gate.sh \
  scripts/e2e/real_hot_path_proof_contract_gate_smoke.sh \
  scripts/e2e/real_hot_path_evidence_drill.sh
```
