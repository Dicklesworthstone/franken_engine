# IDEA-WIZARD-IV Closed-Bead Proof Integrity

`bd-vgj5t` adds an advisory normalizer for closed bead history. It turns
`br` JSON or `.beads/issues.jsonl` snapshots into deterministic proof evidence
that can be attached to saturation reports without reopening, reassigning, or
closing any work.

The normalizer exists because a closed bead is not, by itself, proof that the
requested artifact, validation, and commit evidence landed. The output makes
weak closeout evidence visible before a zero-ready queue is treated as real
saturation.

## Inputs

- `--br-list-json FILE`: `br list --all --json` shaped input.
- `--issues-jsonl FILE`: `.beads/issues.jsonl` shaped input.
- `--git-log-json FILE`: optional commit evidence. When omitted, the script
  reads recent local git history.
- `--artifact-manifest-json FILE`: optional artifact coverage manifest.
- `--source-marker-json FILE`: optional source-marker evidence for closed beads
  whose claimed implementation still has unsupported, placeholder, fail-closed,
  or "not yet implemented" markers in source, tests, or docs.

The script accepts both `br` JSON arrays and objects with an `issues` array. It
also accepts Git JSON arrays or objects with a `commits` array.

## Evidence Classes

Each closed bead receives zero or more evidence classes:

| Class | Meaning |
| --- | --- |
| `direct_commit_reference` | The closeout text includes a commit hash or git history mentions the bead ID. |
| `validation_command_present` | Closeout text includes validation command evidence such as `rch exec`, `cargo test`, script smoke checks, `jq empty`, or `git diff --check`. |
| `artifact_manifest_present` | Closeout text or an artifact manifest references emitted artifacts for the bead. |
| `close_reason_only` | The bead has a close reason, but no stronger proof evidence. |
| `no_evidence` | The bead is closed with no recognized proof evidence. |
| `stale_or_ambiguous_evidence` | Git history only matches title tokens, not the bead ID or closeout commit reference. |
| `semantic_contradiction_marker` | A closed bead has surviving source-marker evidence that contradicts the closed implementation claim. |

`weak_evidence_count` includes any closed bead missing a direct commit
reference. This keeps validation-only and artifact-only closes visible as
degraded proof until a commit or exact bead-linked history receipt is present.
Closed beads with semantic contradiction markers are always high-risk weak
evidence even when they also have commit or validation evidence.

## Artifacts

Each run emits:

- `closed_bead_proof_integrity.json`
- `weak_evidence.jsonl`
- `closed_beads.normalized.json`
- `git_log.normalized.json`
- `source_markers.normalized.json`
- `run_manifest.json`
- `events.jsonl`
- `commands.txt`
- `trace_ids.json`
- `report.md`

The JSON report includes `schema_version`, `source_revision`,
`generated_at_utc`, `decision`, `classification`, `source_freshness`,
`closed_bead_count`, `weak_evidence_count`, `source_marker_count`,
`semantic_contradiction_count`, `proof_strength_buckets`,
`degraded_reasons`, `fail_closed_reasons`, `mutation_policy`, `rch_policy`,
and `artifact_paths`.

## Semantic Contradiction Markers

`--source-marker-json` accepts either an array or an object with `markers`,
`source_markers`, or `result`. Each marker may include:

- `bead_id` or `related_bead_ids`
- `file`
- `line`
- `marker`
- `marker_class`
- `detail`
- `confidence`
- `suggested_next_bead_title`
- `ignored` or `negative_fixture`

Markers flagged as `ignored` or `negative_fixture` are normalized out. This
keeps legitimate negative fixtures from failing the proof-integrity report while
still allowing real source contradictions, such as a closed async bead whose
runtime still says pending promise scheduling is not implemented, to degrade
the zero-ready saturation claim.

## Mutation Boundary

This surface is proof-only and advisory-only. It does not run Cargo or RCH,
mutate git, mutate beads, send Agent Mail, repair Agent Mail, or touch target
directories. It may emit an RCH-wrapped validation command as operator guidance
only.

## Validation

```bash
bash -n scripts/idea_wizard_iv_closed_bead_proof_integrity.sh
bash -n scripts/e2e/idea_wizard_iv_closed_bead_proof_integrity_smoke.sh
bash scripts/e2e/idea_wizard_iv_closed_bead_proof_integrity_smoke.sh check
bash scripts/e2e/idea_wizard_iv_saturation_convergence_contract_smoke.sh check
git diff --check -- docs/IDEA_WIZARD_IV_CLOSED_BEAD_PROOF_INTEGRITY.md scripts/idea_wizard_iv_closed_bead_proof_integrity.sh scripts/e2e/idea_wizard_iv_closed_bead_proof_integrity_smoke.sh docs/idea_wizard_iv_saturation_convergence_v1.json
```
