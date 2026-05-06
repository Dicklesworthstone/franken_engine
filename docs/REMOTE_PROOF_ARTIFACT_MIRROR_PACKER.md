# Remote Proof Artifact Mirror Packer

`scripts/remote_proof_artifact_mirror_packer.sh` creates a
content-addressed mirror manifest and a minimal retrieval pack for resident
remote proof bundles.

It consumes:

- a resident bundle report
- artifact metadata with `sha256` content hashes and replay roles
- a retrieval request naming the roles needed by the operator
- the retrieved artifact path set

It emits deterministic artifacts:

- `artifact_mirror_manifest.json`
- `retrieval_pack.json`
- `retrieval_verification_report.json`
- `commands.txt`
- `events.jsonl`
- `report.md`

## Contract

Verification schema:
`franken-engine.remote-proof-artifact-mirror-verification.v1`

Mirror schema:
`franken-engine.remote-proof-artifact-mirror-manifest.v1`

Retrieval pack schema:
`franken-engine.remote-proof-retrieval-pack.v1`

## Decision Rules

The verifier passes only when all of these are true:

- every artifact has a logical path and a valid 64-character SHA-256 hash
- no single content address maps to multiple logical paths
- every artifact belongs to the resident bundle artifact surface
- selected and retrieved paths avoid broad target-dir or wildcard pulls
- every replay-critical selected artifact is retrieved
- the retrieved path set does not contain undeclared files

Any violation is fail-closed.

## Operator Flow

Use the resident bundle report from
`scripts/resident_remote_proof_bundle_executor.sh`, then provide a compact
artifact metadata list. A replay request should normally ask for `replay` and
`status` roles so operators retrieve `run_manifest.json`, `events.jsonl`,
`commands.txt`, and `bundle_report.json` without pulling a worker target
directory.

Example:

```bash
./scripts/remote_proof_artifact_mirror_packer.sh \
  --bundle-report-json /tmp/bundle_report.json \
  --artifact-files-json /tmp/artifact_files.json \
  --retrieval-request-json /tmp/retrieval_request.json \
  --retrieved-files-json /tmp/retrieved_files.json
```

## Validation

```bash
bash -n scripts/remote_proof_artifact_mirror_packer.sh
bash -n scripts/e2e/remote_proof_artifact_mirror_packer_smoke.sh
bash scripts/e2e/remote_proof_artifact_mirror_packer_smoke.sh check
bash scripts/e2e/remote_proof_artifact_mirror_packer_smoke.sh selftest
```
