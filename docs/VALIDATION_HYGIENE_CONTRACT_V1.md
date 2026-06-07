# Validation Hygiene Contract V1

Status: draft contract
Primary bead: `bd-u9sp4.1`
Parent lane: `bd-u9sp4`
Schema id: `franken-engine.validation-hygiene-report.v1`

## Scope

This contract defines how future validation-hygiene tooling reports whether a
bead's own files are clean when the shared worktree also contains unrelated
dirty files, untracked probes, generated artifacts, or remote validation drift.

The contract is intentionally conservative:

- it classifies dirty context, but never deletes, moves, rewrites, formats, or
  hides unrelated files;
- it preserves the exact command the operator intended to run, especially
  `rch exec -- env ... cargo ...` command shapes;
- it distinguishes "scoped files pass" from "the package or workspace gate is
  blocked by external context";
- it leaves package/workspace validation failures visible even when they are not
  caused by the scoped bead.

## Motivating Failure Modes

The concrete motivating case is `bd-xr2r1`: the focused regression test passed
under `rch` and the scoped diff check passed, but
`cargo fmt -p frankenengine-engine --check` reported formatting failures from
unrelated files including `parser.rs`,
`array_more_methods_bd_isqzc_regression.rs`,
`for_update_comma_sequence_bd_qxkli.rs`, and an untracked
`gl_parser_gap_probe.rs` probe. The correct closeout was not to format or
delete those files. The correct closeout was to record that scoped validation
passed while the broader package format gate was contaminated by unrelated
shared-worktree state.

This contract also covers these recurring classes:

1. Tracked unrelated dirty source files owned by another bead or agent.
2. Untracked probe tests, diagnostic tests, scratch patches, and scratch notes.
3. Generated artifacts or `.actual` / `.snap.new` style outputs that should be
   reported rather than staged by accident.
4. Stale formatting drift in crates newly included by a workspace-level gate.
5. Remote `rch` sync or retrieval behavior that sees files differently from the
   local working copy.
6. Sibling-repository drift that blocks validation before this repository's
   code is compiled or linted.
7. Stale bead state where an implemented bead remains `in_progress` because the
   closeout gate is blocked by unrelated validation infrastructure.

## RCH Sync Contamination Policy

Machine-readable policy:
[`docs/validation_hygiene_rch_sync_policy_v1.json`](./validation_hygiene_rch_sync_policy_v1.json).

The policy decision is deliberately conservative: do not add broad `.rchignore`
rules for untracked tests, probe files, diagnostic Rust files, `*.patch`, or
`*.txt` scratch files. Classify them instead.

The reason is upload-side visibility. In the current RCH transfer pipeline,
source upload is a project-root `rsync` filtered by configured transfer
excludes, runtime excludes, and project-local `.rchignore` patterns. It is not a
Git-tracked-only sync. Therefore an untracked
`crates/franken-engine/tests/gl_parser_gap_probe.rs` can reach the worker and be
discovered by package/workspace validation unless a pattern hides it.

Hiding it with a broad ignore is unsafe because the same naming shape can be an
intentional new regression test for the current bead. A broad exclude such as
`crates/franken-engine/tests/*.rs` or
`crates/franken-engine/tests/*probe*.rs` would let a remote `cargo test` or
`cargo check` report green against a worker tree missing the bead's intended
test input.

Retrieval is different. RCH artifact retrieval pulls declared artifact patterns,
applies retrieval-safe excludes, excludes local source roots that are not
artifact roots, and excludes everything else. That means retrieved artifacts may
appear locally only when they match the declared artifact patterns for the
command class. Source contamination risk is primarily upload-side; retrieval
risk is accidental staging/reporting of generated artifacts, not arbitrary source
overwrite.

The recommended handling is:

| Path shape | RCH upload visibility | Validation handling |
|------------|-----------------------|---------------------|
| `crates/*/tests/*probe*.rs` untracked | Included by default | `untracked_ephemeral_candidate`; block full-gate claims if discoverable. |
| `crates/*/tests/*.rs` untracked without scratch heuristic | Included by default | `untracked_source_candidate`; block full-gate claims until scoped or reviewed. |
| `*.patch` scratch file | Included by default, usually ignored by Cargo | Report for handoff/transfer context; do not stage accidentally. |
| `*.txt` scratch note | Included by default, usually ignored by Cargo | Report for handoff/transfer context; do not stage accidentally. |
| `target/`, `.rch-target/`, `.cargo-target/` | Excluded by default or `.rchignore` | `ignored_artifact`; safe to keep excluded. |
| Retrieved coverage/nextest/criterion artifacts | Retrieved only by declared artifact pattern | `ignored_artifact`; cite if relevant, do not stage accidentally. |

Tools consuming this policy must not rewrite the validation command to hide
untracked files. They may suggest narrower scoped checks, but must keep the
unverified package/workspace gate visible in closeout language.

## Classification Principles

Validation-hygiene tooling must use these stable classifications.

| Class | Meaning | May block scoped closeout | May block package/workspace gate |
|-------|---------|---------------------------|----------------------------------|
| `scoped_file` | File intentionally changed for the current bead and covered by reservation or explicit scope. | Yes | Yes |
| `tracked_unrelated_dirty` | Tracked file with local modifications outside the current bead scope. | No, unless it overlaps scoped paths. | Yes |
| `untracked_ephemeral_candidate` | Untracked scratch, probe, generated, or diagnostic file matching advisory heuristics. | No, unless explicitly scoped. | Yes, if Cargo/rch discovers it. |
| `untracked_source_candidate` | Untracked source-shaped file that does not look ephemeral. | No, unless explicitly scoped. | Yes |
| `ignored_artifact` | Git-ignored build output or generated artifact. | No | Yes, only if the command reads it. |
| `external_environment_blocker` | Failure caused by worker, sibling repo, linker, disk, or manifest state outside scoped files. | No | Yes |
| `unknown_dirty_context` | Dirty item that could not be classified deterministically. | Conservative: yes until reviewed. | Yes |

Classification is advisory. A tool must never infer that a file may be deleted,
formatted, moved, or staged merely because it is classified as ephemeral.

## Advisory Naming Heuristics

These names are candidates for `untracked_ephemeral_candidate` when untracked
and outside the scoped file set:

- `*_probe.rs`
- `*_diag.rs`
- `*_debug.rs`
- `*_irdump.rs`
- files under `tests/` whose names contain `probe`, `diag`, `scratch`, or
  `dump`
- scratch patches such as `*.patch` when not listed as scoped evidence
- scratch text notes such as `*.txt` when not listed as scoped evidence
- generated review files such as `*.actual`, `*.snap.new`, `*.tmp`, and
  run-local manifests under artifact output directories

These names are candidates for `untracked_source_candidate` instead:

- untracked `src/*.rs`, `tests/*.rs`, or `examples/*.rs` that do not match a
  probe/diagnostic/scratch heuristic;
- untracked manifests, schemas, docs, or scripts that look like durable project
  inputs;
- any untracked file named in the bead description, reservation, or commit
  plan.

The classifier must include the reason for each classification. If multiple
heuristics match, the most conservative classification wins.

## Report Schema

A validation-hygiene report is a single JSON document. It may be written into a
future artifact bundle, attached to a bead note, or embedded in a human-readable
closeout. Field names are stable for the V1 contract.

```json
{
  "schema_version": "franken-engine.validation-hygiene-report.v1",
  "report_id": "vh-20260607T012300Z-bd-u9sp4.1",
  "bead_id": "bd-u9sp4.1",
  "source_revision": "3ae61860",
  "generated_at": "2026-06-07T01:23:00Z",
  "repo_root": "/data/projects/franken_engine",
  "command": {
    "argv": [
      "rch",
      "exec",
      "--",
      "env",
      "CARGO_INCREMENTAL=0",
      "RUSTFLAGS=-C linker=cc",
      "cargo",
      "test",
      "-p",
      "frankenengine-engine"
    ],
    "runner": "rch",
    "preserves_original_command": true,
    "working_directory": "/data/projects/franken_engine",
    "target_scope": "package"
  },
  "outcome": {
    "status": "blocked_by_unrelated_context",
    "exit_code": 101,
    "first_blocker": {
      "class": "tracked_unrelated_dirty",
      "path": "crates/franken-engine/src/parser.rs",
      "summary": "cargo fmt reported formatting drift outside scoped files"
    },
    "scoped_files_clean": true,
    "package_or_workspace_gate_clean": false
  },
  "scoped_files": [
    {
      "path": "crates/franken-engine/src/lowering_pipeline.rs",
      "role": "implementation",
      "git_state": "modified",
      "reserved": true,
      "validated_by": ["focused_test", "diff_check"],
      "status": "clean"
    }
  ],
  "tracked_unrelated_dirty": [
    {
      "path": "crates/franken-engine/src/parser.rs",
      "owner_hint": null,
      "classification_reason": "tracked modified file outside scoped_files",
      "observed_by_command": true
    }
  ],
  "untracked_ephemeral_candidates": [
    {
      "path": "crates/franken-engine/tests/gl_parser_gap_probe.rs",
      "classification_reason": "untracked test file matches *_probe.rs",
      "observed_by_command": true
    }
  ],
  "untracked_source_candidates": [],
  "ignored_artifacts": [],
  "external_environment_blockers": [],
  "reservation_snapshot": {
    "agent": "SilverPeak",
    "exclusive_paths": [
      "crates/franken-engine/src/lowering_pipeline.rs"
    ],
    "missing_expected_reservations": []
  },
  "rch_context": {
    "used": true,
    "sync_scope": "implementation-defined",
    "retrieval_status": "not_applicable",
    "worker_blocker": null
  },
  "no_delete_guarantee": {
    "performed_deletions": false,
    "performed_reverts": false,
    "performed_unrelated_formatting": false,
    "performed_unrelated_staging": false
  }
}
```

## Outcome Status Values

| Status | Meaning |
|--------|---------|
| `pass` | Scoped files and requested gate passed. |
| `scoped_pass_with_external_blockers` | Scoped files passed, but broader validation could not be completed because of external or unrelated blockers. |
| `blocked_by_unrelated_context` | The first actionable blocker is outside the scoped file set. |
| `blocked_by_environment` | The first actionable blocker is remote worker, sibling repo, linker, disk, or other environment state. |
| `fail_scoped_files` | The scoped bead files failed validation. |
| `inconclusive` | The classifier cannot prove whether the blocker belongs to the scoped bead. |

`pass` is the only all-green status. Every other status must preserve the exact
failed command and first blocker.

## Required Examples

### Clean Scoped Change

```json
{
  "schema_version": "franken-engine.validation-hygiene-report.v1",
  "bead_id": "bd-example",
  "outcome": {
    "status": "pass",
    "scoped_files_clean": true,
    "package_or_workspace_gate_clean": true,
    "first_blocker": null
  },
  "scoped_files": [
    {
      "path": "docs/VALIDATION_HYGIENE_CONTRACT_V1.md",
      "reserved": true,
      "status": "clean"
    }
  ],
  "tracked_unrelated_dirty": [],
  "untracked_ephemeral_candidates": [],
  "no_delete_guarantee": {
    "performed_deletions": false,
    "performed_reverts": false,
    "performed_unrelated_formatting": false,
    "performed_unrelated_staging": false
  }
}
```

### Unrelated Tracked Formatting Drift

```json
{
  "schema_version": "franken-engine.validation-hygiene-report.v1",
  "bead_id": "bd-xr2r1",
  "outcome": {
    "status": "blocked_by_unrelated_context",
    "scoped_files_clean": true,
    "package_or_workspace_gate_clean": false,
    "first_blocker": {
      "class": "tracked_unrelated_dirty",
      "path": "crates/franken-engine/src/parser.rs",
      "summary": "format check failed outside scoped files"
    }
  },
  "scoped_files": [
    {
      "path": "crates/franken-engine/src/lowering_pipeline.rs",
      "reserved": true,
      "status": "clean"
    }
  ],
  "tracked_unrelated_dirty": [
    {
      "path": "crates/franken-engine/src/parser.rs",
      "classification_reason": "tracked modified file outside scoped_files",
      "observed_by_command": true
    }
  ]
}
```

### Untracked Probe Contamination

```json
{
  "schema_version": "franken-engine.validation-hygiene-report.v1",
  "bead_id": "bd-example-probe",
  "outcome": {
    "status": "blocked_by_unrelated_context",
    "scoped_files_clean": true,
    "package_or_workspace_gate_clean": false,
    "first_blocker": {
      "class": "untracked_ephemeral_candidate",
      "path": "crates/franken-engine/tests/gl_parser_gap_probe.rs",
      "summary": "untracked probe test was discovered by package validation"
    }
  },
  "untracked_ephemeral_candidates": [
    {
      "path": "crates/franken-engine/tests/gl_parser_gap_probe.rs",
      "classification_reason": "untracked test file matches *_probe.rs",
      "observed_by_command": true
    }
  ],
  "no_delete_guarantee": {
    "performed_deletions": false,
    "performed_reverts": false,
    "performed_unrelated_formatting": false,
    "performed_unrelated_staging": false
  }
}
```

### Mixed Tracked and Untracked Blockers

```json
{
  "schema_version": "franken-engine.validation-hygiene-report.v1",
  "bead_id": "bd-example-mixed",
  "outcome": {
    "status": "blocked_by_unrelated_context",
    "scoped_files_clean": true,
    "package_or_workspace_gate_clean": false,
    "first_blocker": {
      "class": "tracked_unrelated_dirty",
      "path": "crates/franken-engine/tests/golden_lowering.rs",
      "summary": "tracked dirty file appears before untracked probe in gate output"
    }
  },
  "tracked_unrelated_dirty": [
    {
      "path": "crates/franken-engine/tests/golden_lowering.rs",
      "classification_reason": "tracked modified file outside scoped_files",
      "observed_by_command": true
    }
  ],
  "untracked_ephemeral_candidates": [
    {
      "path": ".jh_zs4d5_ircontract.patch",
      "classification_reason": "untracked patch outside scoped_files",
      "observed_by_command": false
    }
  ],
  "untracked_source_candidates": [
    {
      "path": "crates/franken-engine/src/moonshot_ranking_report.rs",
      "classification_reason": "untracked src/*.rs file without probe heuristic",
      "observed_by_command": false
    }
  ]
}
```

## AGENTS.md Interactions

The validation-hygiene implementation must enforce these AGENTS.md-aligned
behaviors:

1. Reserve scoped paths before editing or before claiming that a file is owned
   by the current bead.
2. Never delete a file or directory, including files created during the current
   session, without explicit written user permission.
3. Never run destructive cleanup commands to make validation easier.
4. Never revert, format, move, stage, or commit another agent's dirty file unless
   the user explicitly requested that exact action.
5. Preserve `br` status truth: an implemented bead that cannot close because of
   unrelated validation blockers should be `blocked`, not left silently
   `in_progress`.
6. Preserve the original Cargo/rch command shape in `command.argv`; wrappers may
   add reporting around a command, but must not silently substitute a different
   validation target.
7. Commit only scoped files and bead metadata. Scratch probes, generated outputs,
   and unrelated dirty files remain unstaged unless they are explicitly scoped.

## Non-Goals

This contract does not authorize:

- deletion or quarantine-by-move of untracked files;
- automatic formatting of unrelated files;
- automatic staging of unrelated tracked or untracked files;
- hiding package/workspace failures after scoped checks pass;
- converting package validation into a narrower command without recording that
  the original package/workspace gate remains unverified;
- deciding ownership of a file without reservation, bead notes, or explicit user
  direction;
- treating an `rch` worker failure as a code failure without preserving the
  first hard environment blocker.

## Fixture Plan for Follow-On E2E Tests

The implementation beads should add deterministic no-delete fixtures that cover:

1. Clean scoped doc change:
   - one scoped file,
   - no unrelated dirty files,
   - expected status `pass`.
2. Tracked unrelated formatting drift:
   - one scoped file,
   - one tracked unrelated modified Rust file,
   - expected status `blocked_by_unrelated_context`.
3. Untracked probe contamination:
   - one scoped file,
   - one untracked `*_probe.rs` test,
   - expected classification `untracked_ephemeral_candidate`.
4. Untracked durable source candidate:
   - one untracked `src/*.rs` file that does not match probe heuristics,
   - expected classification `untracked_source_candidate`.
5. Mixed tracked and untracked blockers:
   - at least one tracked unrelated dirty file,
   - at least one untracked scratch patch,
   - at least one untracked source candidate,
   - deterministic `first_blocker` ordering.
6. External environment blocker:
   - synthetic `rch` log with a remote linker, sibling manifest, disk, or
     retrieval failure before repo lint/test execution,
   - expected status `blocked_by_environment`.
7. No-delete invariant:
   - fixture files exist before and after the tool run,
   - inode/path list is unchanged,
   - report sets every `no_delete_guarantee` mutation field to `false`.

The fixture harness should run locally and under `rch` where it invokes Cargo.
Non-Cargo shell validation may remain local. Each fixture should write
`commands.txt`, `events.jsonl`, and a report JSON so later runbooks can cite the
same evidence shape as the rest of the project.

## Operator Closeout Language

When scoped validation passes but broader validation is contaminated, closeout
notes should use this shape:

```text
Scoped validation: PASS for <paths/tests>.
Package/workspace validation: BLOCKED by unrelated context.
First blocker: <class> <path or environment> - <short exact failure>.
No deletion, revert, unrelated formatting, or unrelated staging was performed.
Original command preserved: <command>.
```

When the scoped files fail, closeout notes should say `Scoped validation: FAIL`
and point at the scoped file/error first. The hygiene classifier must not be used
to downgrade a real scoped failure into an external blocker.
