# Proof Artifact Contract V1

`franken-engine.proof-artifact-manifest.v1` is the shared artifact bundle for
user-facing proof gates and proof examples. A gate can keep its existing
domain-specific report, but every observed proof run should also emit this
standard bundle:

- `manifest.json`: bundle identity, commit hash, gate name, status, rerun
  command, artifact paths, related claims/beads, commands, artifact hashes,
  verifier outputs, and freshness metadata.
- `commands.txt`: command transcript for the run.
- `events.jsonl`: structured step log. Each row should include
  `schema_version`, `event_name`, `severity`, `step_id`, `command_id`,
  `artifact_path`, `artifact_sha256`, `exit_code`, `duration_ms`, `decision`,
  and `remediation`.
- `report.json`: machine-readable summary with status, event count, failure
  count, rerun command, report paths, and findings.
- `report.md`: human-readable summary for reviewers.
- `redaction_policy.json`: the redaction policy used before commands are copied
  into standard proof reports.

The Rust schema lives in `crates/franken-engine/src/proof_artifact.rs`. Shell
gates should source `scripts/lib/proof_artifact_contract.sh` and finish by
calling `proof_contract_write_standard_bundle` after their domain-specific
`events.jsonl` and source report are written.

The first wired gates are:

- `scripts/run_claim_to_proof_matrix_gate.sh`
- `scripts/e2e/readme_cli_workflow_smoke.sh`
- `examples/02_signed_decision_receipt/verify.sh`
- `scripts/e2e/proof_artifact_contract_smoke.sh`

New proof gates should prefer repository-relative artifact paths. The helper
normalizes paths under the repo root before writing the shared manifest so that
artifacts remain reproducible across local and remote runners.

Rerun example:

```bash
./scripts/e2e/proof_artifact_contract_smoke.sh
```
