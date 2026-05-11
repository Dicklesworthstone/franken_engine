# IDEA-WIZARD-IV Zero-Ready Saturation Drill

`bd-aqijn` adds a replayable drill for zero-ready saturation evidence. It
composes the IDEA-WIZARD-IV child packets into a single convergence report so
an empty ready queue is never treated as project saturation without proof.

The drill is proof-only. It consumes preserved, real-shaped snapshots and runs
the child packet scripts into `step_logs/` and child artifact directories. It
does not mutate beads, send Agent Mail, repair Agent Mail, run Cargo, run RCH,
or change queue policy.

## Inputs

Required:

- `--br-ready-json FILE`
- `--br-in-progress-json FILE`
- `--mail-health-json FILE`
- `--rch-status-json FILE`
- `--git-status-json FILE`
- one of `--br-list-json FILE` or `--issues-jsonl FILE`
- at least one `--changed-path PATH`

Optional resource inputs are passed through to the heatmap child:

- `--queue-depth-json FILE`
- `--target-dir-heatmap-json FILE`
- `--proof-cache-locality-json FILE`
- `--pressure-metrics-json FILE`
- `--archive-pressure-json FILE`
- `--resource-envelope-json FILE`

## Artifacts

Each run emits:

- `run_manifest.json`
- `events.jsonl`
- `commands.txt`
- `trace_ids.json`
- `saturation_convergence_report.json`
- `step_logs/step_*.log`
- child directories for closed-bead proof, coordination health, validation
  impact, and resource proof heatmap packets

`scripts/e2e/idea_wizard_iv_zero_ready_saturation_replay.sh` validates a
preserved bundle without rerunning the child scripts.

## Decision Rules

The report is `green` only when:

- `br_ready_count` is zero
- tracked worktree evidence is clean
- every child packet is present, well-formed, and green or healthy
- no child report is stale, malformed, or missing

Red Agent Mail, weak closed-bead proof, missing optional resource metrics, or a
degraded validation/resource plan produces `degraded` evidence. Nonzero ready
work, malformed required inputs, local fallback contamination, missing child
reports, or dirty tracked worktree evidence fails closed.

## Validation

```bash
bash -n scripts/idea_wizard_iv_zero_ready_saturation_drill.sh
bash -n scripts/e2e/idea_wizard_iv_zero_ready_saturation_replay.sh
bash -n scripts/e2e/idea_wizard_iv_zero_ready_saturation_drill_smoke.sh
bash scripts/e2e/idea_wizard_iv_zero_ready_saturation_drill_smoke.sh check
bash scripts/e2e/idea_wizard_iv_saturation_convergence_contract_smoke.sh check
git diff --check -- docs/IDEA_WIZARD_IV_ZERO_READY_SATURATION_DRILL.md scripts/idea_wizard_iv_zero_ready_saturation_drill.sh scripts/e2e/idea_wizard_iv_zero_ready_saturation_replay.sh scripts/e2e/idea_wizard_iv_zero_ready_saturation_drill_smoke.sh docs/idea_wizard_iv_saturation_convergence_v1.json
```
