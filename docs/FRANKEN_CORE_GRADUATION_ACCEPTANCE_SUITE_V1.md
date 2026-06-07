# Franken-Core Graduation Acceptance Suite V1

Status: active
Primary bead: `bd-4w7h9.8`
Parent wave: `bd-4w7h9`
Machine-readable contract: `docs/franken_core_graduation_acceptance_suite_v1.json`

## Scope

This suite composes the IDEA-WIZARD-V franken-core graduation artifacts into one
operator-facing decision. It was the pre-topology acceptance package that
authorized opening the explicit membership bead. The later topology bead
`bd-cixqu.10.7` includes `crates/franken-core` in the root workspace.

## Acceptance Command

```bash
bash scripts/franken_core_graduation_acceptance_suite.sh --output-dir /tmp/franken-core-graduation-acceptance
```

The command writes:

- `acceptance_report.json`
- `events.jsonl`
- `commands.txt`
- `report.md`

## Decision Vocabulary

| Decision | Meaning |
| --- | --- |
| `workspace_membership_complete` | Current post-J.7 decision: the included root topology and guard artifacts are coherent. |
| `fail_closed` | Current post-J.7 fail-closed decision: stale artifacts, failed child smokes, or manifest drift block the claim. |
| `ready_for_explicit_workspace_membership_bead` | Historical pre-J.7 decision: evidence package is coherent; a later topology bead may propose membership. |
| `remain_excluded` | Historical pre-J.7 fail-closed decision: missing, stale, contradictory, or downgraded evidence kept the crate out of the workspace. |

Post-J.7, the status truth gate is the live authority for membership state.

## Final Proof Commands For The Topology Bead

```bash
rch exec -- env CARGO_TARGET_DIR=/tmp/rch_target_franken_engine_franken_core_membership CARGO_INCREMENTAL=0 CARGO_BUILD_JOBS=1 cargo check --all-targets
rch exec -- env CARGO_TARGET_DIR=/tmp/rch_target_franken_engine_franken_core_membership CARGO_INCREMENTAL=0 CARGO_BUILD_JOBS=1 cargo clippy --all-targets -- -D warnings
rch exec -- env CARGO_TARGET_DIR=/tmp/rch_target_franken_engine_franken_core_membership CARGO_INCREMENTAL=0 CARGO_BUILD_JOBS=1 cargo test
```

## Coordination Fallback

Agent Mail is not required for this proof command. If Agent Mail is corrupt or
unavailable, operators should use Beads assignment plus Git commits as the soft
lock and record that limitation in the handoff.

## Validation

```bash
jq empty docs/franken_core_graduation_acceptance_suite_v1.json
bash -n scripts/franken_core_graduation_acceptance_suite.sh
bash -n scripts/e2e/franken_core_graduation_acceptance_suite_smoke.sh
bash scripts/e2e/franken_core_graduation_acceptance_suite_smoke.sh check
bash scripts/e2e/franken_core_graduation_acceptance_suite_smoke.sh negative
git diff --check -- docs/FRANKEN_CORE_GRADUATION_ACCEPTANCE_SUITE_V1.md docs/franken_core_graduation_acceptance_suite_v1.json scripts/franken_core_graduation_acceptance_suite.sh scripts/e2e/franken_core_graduation_acceptance_suite_smoke.sh
```
