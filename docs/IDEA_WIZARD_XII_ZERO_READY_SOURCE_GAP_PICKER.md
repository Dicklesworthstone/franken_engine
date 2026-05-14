# IDEA-WIZARD-XII Zero-Ready Source-Gap Picker

`bd-n51l8.4` adds an advisory picker for zero-ready tracker states. It converts
source-marker evidence into bounded proposed beads only when both `br ready` and
`br list --status open` snapshots are empty.

The picker exists to avoid declaring saturation while source files, tests, or
docs still carry explicit unsupported, fail-closed, placeholder, or TODO
markers. It is read-only and emits review artifacts; it does not create beads.

## Inputs

- `--br-ready-json FILE`: `br ready --json` snapshot.
- `--br-open-json FILE`: `br list --status open --json` snapshot.
- `--closed-beads-json FILE` or `--issues-jsonl FILE`: closed history used for
  deduplication against old work.
- `--source-marker-json FILE`: source markers from a scan or proof-integrity
  surface.

Source markers may be an array or an object with `markers`, `source_markers`, or
`result`. Each marker may include `bead_id`, `related_bead_ids`, `file`, `line`,
`marker`, `marker_class`, `detail`, `confidence`, `validation_scope`,
`suggested_next_bead_title`, `ignored`, or `negative_fixture`.

Markers flagged as `ignored` or `negative_fixture` are normalized out before
ranking.

## Outputs

Each run emits:

- `zero_ready_source_gap_picker.json`
- `proposed_beads.json`
- `suppressed_candidates.json`
- `source_markers.normalized.json`
- `br_commands.sh`
- `run_manifest.json`
- `events.jsonl`
- `commands.txt`
- `report.md`
- `trace_ids.json`

`br_commands.sh` is a review transcript only. The picker never runs the
commands and never mutates `.beads`.

## Decisions

| Decision | Meaning |
| --- | --- |
| `not_zero_ready` | Ready or open tracker input is non-empty; no proposals are emitted. |
| `proposals_emitted` | Zero-ready input had at least one actionable source marker. |
| `no_actionable_source_gap` | Zero-ready input had no actionable source markers after filtering and dedupe. |

The report records `ready_count`, `open_count`, `closed_bead_count`,
`source_marker_count`, `proposal_count`, `suppressed_count`, and
`duplicate_suppressed_count`.

## Ranking and Deduplication

Candidates are ranked by:

- signal quality: unsupported, not-implemented, fail-closed, placeholder, and
  TODO markers are high-signal;
- user impact: runtime, core, security, and IFC paths rank above docs/scripts;
- validation cost: low-cost shell/docs checks get a small boost.

The picker suppresses markers that match open/ready work by title, source path,
or marker text. It also suppresses closed-bead duplicates unless the marker has
a clear follow-up signal such as `suggested_next_bead_title`, high confidence,
or an unsupported semantic marker. That prevents closed-but-false claims from
hiding real debt while still avoiding duplicate queue churn.

## Mutation Boundary

This surface is advisory-only. It does not run Cargo or RCH, mutate git, mutate
beads, send Agent Mail, repair Agent Mail, or touch worker state.

## Validation

```bash
bash -n scripts/idea_wizard_xii_zero_ready_source_gap_picker.sh
bash -n scripts/e2e/idea_wizard_xii_zero_ready_source_gap_picker_smoke.sh
bash scripts/e2e/idea_wizard_xii_zero_ready_source_gap_picker_smoke.sh check
shellcheck -x scripts/idea_wizard_xii_zero_ready_source_gap_picker.sh scripts/e2e/idea_wizard_xii_zero_ready_source_gap_picker_smoke.sh
git diff --check -- docs/IDEA_WIZARD_XII_ZERO_READY_SOURCE_GAP_PICKER.md scripts/idea_wizard_xii_zero_ready_source_gap_picker.sh scripts/e2e/idea_wizard_xii_zero_ready_source_gap_picker_smoke.sh scripts/testdata/goldens/idea_wizard_xii_zero_ready_source_gap_picker.golden
```
