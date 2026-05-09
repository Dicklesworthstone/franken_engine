# Swarm Proof Broker

`bd-ua5n2.1`

The proof broker contract defines the request fingerprint and verdict receipt
shape used by the future broker control plane. It is advisory-only: a receipt can
explain whether a proof looks reusable, stale, contaminated, or refused, but it
cannot close a bead or mutate the queue by itself.

## Request Fingerprint

Every proof request id is derived from canonical JSON with sorted object keys and
a stable `spbreq-` prefix. The fingerprint includes:

- normalized command argv
- command kind
- accepted environment allowlist
- package, target kind, target name, and test filter
- feature flags
- git commit, tree state, and dirty paths
- dependency closure roots
- RCH version and posture
- target-dir policy
- requested proof purpose and requesting agent
- source evidence from br, Agent Mail, git, RCH, and artifacts

Command argv remains ordered because argument order is semantic. Sets such as
feature flags, dirty paths, dependency roots, and evidence ids are sorted before
hashing. Environment values are accepted only when their names are in the
contract allowlist.

## Verdict Receipts

Receipts use `franken-engine.swarm-proof-broker-verdict-receipt.v1` and one of
six statuses:

- `passed`: eligible for reuse only while fresh and artifact-complete.
- `failed`: useful as failure evidence, never as green proof.
- `stale`: invalidated by source, dependency, toolchain, RCH, or TTL drift.
- `contaminated`: local fallback or dirty overlap was observed.
- `inconclusive`: required evidence or artifacts are missing.
- `reuse_refused`: evidence is sufficient to reject reuse for the request.

Only `passed` can be reuse-eligible, and even that remains evidence-first. The
broker cannot close beads, release reservations, send Agent Mail, change worker
state, run Cargo, or invoke RCH.

## Fail-Closed Reasons

The contract requires remediation text for each fail-closed reason:

- `proof_failed`
- `changed_source`
- `changed_dependency_root`
- `changed_rch_version`
- `changed_toolchain`
- `local_fallback`
- `dirty_workspace_mismatch`
- `expired_ttl`
- `incomplete_artifact_bundle`
- `narrower_command_mismatch`
- `wider_command_mismatch`
- `missing_evidence`
- `unsupported_command_shape`

Local fallback contamination, dirty workspace mismatch, incomplete artifact
bundles, unsupported command shapes, and narrower or wider proof substitutions
must fail closed. A wider all-targets proof does not automatically satisfy an
exact filtered proof until the later equivalence classifier emits explicit
evidence.

## RCH Hygiene

Rust proof commands should preserve the direct shape:

```bash
rch exec -- env CARGO_INCREMENTAL=0 CARGO_BUILD_JOBS=1 CARGO_TARGET_DIR=/tmp/rch_target_franken_engine_<lane> cargo test -p <package> <filter> --lib -- --nocapture
```

The broker contract rejects bare local Cargo, shell-wrapped RCH commands that can
fall open into local execution, missing target-dir policy, and transcripts with
local fallback markers.

## Validation

```bash
jq empty docs/swarm_proof_broker_contract_v1.json scripts/testdata/swarm_proof_broker/contracts/cases.json
bash -n scripts/e2e/swarm_proof_broker_contract_smoke.sh
bash scripts/e2e/swarm_proof_broker_contract_smoke.sh check
git diff --check -- docs/SWARM_PROOF_BROKER.md docs/swarm_proof_broker_contract_v1.json scripts/e2e/swarm_proof_broker_contract_smoke.sh scripts/testdata/swarm_proof_broker/contracts/cases.json
```
