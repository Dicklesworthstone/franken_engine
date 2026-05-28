# Golden File Provenance — `tests/goldens/` (JSON) — TOMBSTONE

This directory has been fully drained into the canonical
`tests/golden/` tree. The stub remains in place per the
[bd-ub6x8.6.1 RATIONALIZATION decision](../../../../docs/operator-gates/GOLDEN_DIRECTORIES_RATIONALIZATION.md)
so that historical references in commit messages, issue threads, and
release notes still resolve to a live file with forwarding pointers.

Live inventory and review process now live at
`tests/golden/PROVENANCE.md`. Regenerate any fixture with
`UPDATE_GOLDENS=1 cargo test ...` (project-wide convention, bd-ub6x8.2).

## Status

**Drained.** All previously-resident subdirectories migrated into
`tests/golden/<feature>/`:

| Old path                                 | New path                                 | bead         |
|------------------------------------------|------------------------------------------|--------------|
| `tests/goldens/ir/`                      | `tests/golden/ir/`                       | bd-ub6x8.6.2 |
| `tests/goldens/evidence/`                | `tests/golden/evidence_bundle/`          | bd-ub6x8.6.2 |
| `tests/goldens/react_compilation/`       | `tests/golden/react_compilation/`        | bd-ub6x8.6.2 |
| `tests/goldens/benchmark_diagnostic/`    | `tests/golden/benchmark_diagnostic/`     | bd-ub6x8.6.2 |
| `tests/golden_tests/` (sibling root)     | `tests/golden/cli/`                      | bd-ub6x8.6.2 |
| `tests/golden_vectors/` (sibling root)   | `tests/golden/wire_vectors/`             | bd-ub6x8.6.3 |
| `tests/goldens/certificates/`            | `tests/golden/certificates/`             | bd-ub6x8.6.4 |
| `tests/goldens/policy_theorem_compiler/` | `tests/golden/policy_theorem_compiler/`  | bd-ub6x8.6.4 |

No subdirectory fixtures remain at `tests/goldens/`.
