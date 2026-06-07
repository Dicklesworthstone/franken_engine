# Validation Hygiene Runbook

Status: operator runbook
Primary bead: `bd-u9sp4.7`
Related contract: [`VALIDATION_HYGIENE_CONTRACT_V1.md`](./VALIDATION_HYGIENE_CONTRACT_V1.md)
RCH sync policy: [`validation_hygiene_rch_sync_policy_v1.json`](./validation_hygiene_rch_sync_policy_v1.json)

Use this runbook when a bead's scoped files are ready but the shared worktree
contains unrelated dirty files, untracked probes, generated artifacts, or remote
validation failures. The goal is honest closeout evidence, not cleanup.

## Rule

Never delete, revert, move, format, stage, or commit unrelated files to make a
validation command pass. If a package/workspace gate is blocked by unrelated
context, say that directly and preserve the original command evidence.

## Scope Levels

| Scope | What it can prove | What it cannot prove |
|-------|-------------------|----------------------|
| Scoped file check | The bead's explicitly scoped files pass a narrow check such as `git diff --check -- <paths>` or `bash -n <scripts>`. | Package/workspace health. |
| Focused test | A relevant target for the bead passes. | Full package/workspace health unless it is the full gate. |
| Package gate | One package's configured validation passes. | Other workspace members or sibling repos. |
| Workspace gate | Full repository validation passes. | Future dirty-tree changes after the run. |

A scoped pass may be enough to commit a docs/shell-only bead when the bead does
not change Rust semantics and broader gates are blocked by unrelated context. It
is not enough to claim `cargo check --all-targets`, `cargo test`, or
`cargo clippy --all-targets -- -D warnings` is green.

## Tool Flow

1. Reserve scoped paths with Agent Mail.
2. Run preflight before or near closeout:

```bash
scripts/validation_hygiene_preflight.sh \
  --scope <path> \
  --bead-id <bd-id> \
  --agent "$AGENT_NAME" \
  --format text
```

3. Run the narrow checks that match the changed files:

```bash
git diff --check -- <scoped paths>
bash -n <changed shell scripts>
shellcheck -x <changed shell scripts>
jq empty <changed json files>
```

4. For a command that should be classified, wrap it:

```bash
scripts/validation_hygiene_wrapper.sh \
  --scope <path> \
  --bead-id <bd-id> \
  --case-id closeout \
  -- \
  rch exec -- env CARGO_TARGET_DIR=/data/tmp/franken_engine-validation \
    CARGO_INCREMENTAL=0 RUSTFLAGS='-C linker=cc' \
    cargo test -p frankenengine-engine <focused-target>
```

Use the same shape for heavy package/workspace gates:

```bash
scripts/validation_hygiene_wrapper.sh \
  --scope <path> \
  --bead-id <bd-id> \
  --case-id cargo-check-all-targets \
  -- \
  rch exec -- env CARGO_TARGET_DIR=/data/tmp/franken_engine-validation \
    CARGO_INCREMENTAL=0 RUSTFLAGS='-C linker=cc' \
    cargo check --all-targets
```

The wrapper exits with the original command status. Do not treat wrapper success
or failure as separate from the command it wrapped; read the embedded classifier
report.

## Dirty-Tree Examples

Untracked probe visible to package validation:

```text
First blocker: untracked_ephemeral_candidate crates/franken-engine/tests/gl_parser_gap_probe.rs
Interpretation: scoped files may be clean, but package/workspace validation is contaminated.
Action: leave the probe file alone unless it is explicitly scoped to your bead.
```

Tracked unrelated drift:

```text
First blocker: tracked_unrelated_dirty crates/franken-engine/tests/golden_lowering.rs
Interpretation: another tracked file is dirty outside the scoped paths.
Action: do not format, revert, or stage it. Report the blocker.
```

Untracked source-shaped candidate:

```text
First blocker: untracked_source_candidate crates/franken-engine/src/moonshot_ranking_report.rs
Interpretation: the file may be intentional durable source, not scratch.
Action: do not hide it with .rchignore. Scope it or leave it for its owner.
```

RCH infrastructure blocker:

```text
First blocker: external_environment_blocker collect2: fatal error: ld terminated with signal 7 [Bus error]
Interpretation: remote validation did not reach a source verdict.
Action: cite the worker/linker blocker and preserve the first hard failure line.
```

Sibling repo manifest blocker:

```text
First blocker: external_environment_blocker failed to parse /dp/frankensqlite/crates/fsqlite/Cargo.toml
Interpretation: validation stopped before this repository's code was checked.
Action: report sibling/environment blocker; do not mark scoped Rust code green from that run.
```

## Closeout Templates

Full pass:

```text
Scoped validation: PASS for <paths>.
Package/workspace validation: PASS.
Commands:
- <exact command 1>
- <exact command 2>
No deletion, revert, unrelated formatting, or unrelated staging was performed.
Commit: <sha>.
```

Focused pass plus unrelated package blocker:

```text
Scoped validation: PASS for <paths/tests>.
Package/workspace validation: BLOCKED by unrelated context.
First blocker: <tracked_unrelated_dirty|untracked_ephemeral_candidate|untracked_source_candidate|ignored_artifact> <path> - <exact summary>.
Original command preserved: <exact command>.
No deletion, revert, unrelated formatting, or unrelated staging was performed.
```

In-scope failure:

```text
Scoped validation: FAIL.
Failing scoped file/test: <path or target>.
First blocker: scoped_file <path> - <exact summary>.
Package/workspace validation: not claimed.
Next action: fix scoped failure before commit or block the bead.
```

RCH infrastructure failure:

```text
Scoped validation: NOT PROVEN by this run.
Package/workspace validation: BLOCKED by environment.
First blocker: external_environment_blocker - <first hard failure line>.
Original command preserved: <rch exec -- env ... cargo ...>.
No deletion, revert, unrelated formatting, or unrelated staging was performed.
```

Unknown classifier result:

```text
Scoped validation: INCONCLUSIVE.
Classifier status: inconclusive.
First blocker: unknown or absent.
Original command preserved: <exact command>.
Closeout: block or rerun with better transcript; do not claim green.
```

## Commit Checklist

1. Reserve scoped files and `.beads/issues.jsonl`.
2. Claim the bead with `br update <id> --claim --actor "$AGENT_NAME" --json`.
3. Announce start in Agent Mail using the bead id as `thread_id`.
4. Implement only scoped files.
5. Run preflight and relevant scoped validation.
6. Run wrapped heavy Cargo validation through `rch exec -- env ... cargo ...`
   when Rust/package/workspace proof is required.
7. Classify blockers; keep unrelated package/workspace blockers visible.
8. Close or block the bead with exact validation evidence.
9. Run `br sync --flush-only --json`.
10. Stage only scoped files and `.beads/issues.jsonl`.
11. Inspect `git diff --cached --name-status` and `git diff --cached --check`.
12. Commit with `AGENT_NAME=<agent> git commit ...`.
13. Push with `AGENT_NAME=<agent> git push origin main`.
14. Release file reservations.
15. Notify peers in Agent Mail with commit SHA, validation, and deferred blockers.

## Quick Verification

Run the hygiene tool selftests after changing the lane:

```bash
scripts/e2e/validation_hygiene_classifier_smoke.sh selftest
scripts/e2e/validation_hygiene_wrapper_smoke.sh selftest
scripts/e2e/validation_hygiene_preflight_smoke.sh selftest
scripts/e2e/validation_hygiene_no_delete_e2e.sh selftest
```

These tests use temporary fixture repositories. They do not authorize cleanup of
the live shared worktree.
