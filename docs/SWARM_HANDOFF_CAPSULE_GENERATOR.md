# Swarm Handoff Capsule Generator

`bd-d5kxj` adds a deterministic, read-only handoff capsule for compaction,
agent takeover, and dirty multi-agent sessions. The machine contract is
[`docs/swarm_handoff_capsule_generator_contract_v1.json`](./swarm_handoff_capsule_generator_contract_v1.json).

The generator consumes preserved JSON snapshots. It does not read source file
contents, send Agent Mail, repair the Agent Mail database, run Cargo, invoke
`rch`, mutate `br`, mutate git, release reservations, or change worker state.
The privacy boundary is explicit: source file contents are never copied.

## Inputs

Required:

- `--git-status-json`: branch, main-ref divergence, and dirty path metadata.
- `--br-state-json`: ready, in-progress, active bead, and current agent state.

Optional:

- `--owned-paths-json`: exact path list owned by this agent/session.
- `--recent-commits-json`: recent commit summaries.
- `--rch-jobs-json`: active RCH job/process snapshots.
- `--validation-receipts-json`: validation receipts and transcript digests.
- `--mail-health-json`: Agent Mail health output or captured failure JSON.
- `--operator-notes-json`: note IDs and digests. Bodies are not copied.

## Output

Each run emits:

- `swarm_handoff_capsule.json`
- `swarm_handoff_capsule.md`
- `handoff_commands.txt`
- `events.jsonl`

The JSON capsule includes branch/main divergence, owned versus unrelated dirty
paths, active bead state, recent commits, RCH job state, validation receipts,
Agent Mail degraded status, next actions, and mutation policy.

## Decisions

`ready` means the supplied snapshots have no unrelated dirty paths, no active
RCH jobs, no degraded Agent Mail status, and no failed/stale validation receipts.

`degraded` means the handoff is still usable, but the next agent must account
for visible coordination risk such as unrelated dirty paths, active RCH work, or
red Agent Mail.

`blocked` means the capsule observed a missing branch snapshot or a validation
receipt that failed, is stale, or is not reuse-eligible.

## Validation

```bash
jq empty docs/swarm_handoff_capsule_generator_contract_v1.json
bash -n scripts/swarm_handoff_capsule_generator.sh scripts/e2e/swarm_handoff_capsule_generator_smoke.sh
./scripts/e2e/swarm_handoff_capsule_generator_smoke.sh selftest
git diff --check -- docs/SWARM_HANDOFF_CAPSULE_GENERATOR.md docs/swarm_handoff_capsule_generator_contract_v1.json scripts/swarm_handoff_capsule_generator.sh scripts/e2e/swarm_handoff_capsule_generator_smoke.sh scripts/testdata/swarm_handoff_capsule_generator/cases.json
```

Heavy Rust validation examples in generated recommendations or operator notes
remain evidence only. Any executable heavy Cargo proof must use direct RCH with
an explicit target directory, for example:

```bash
rch exec -- env CARGO_TARGET_DIR=/tmp/rch_target_franken_engine_handoff_capsule CARGO_INCREMENTAL=0 CARGO_BUILD_JOBS=1 cargo check --all-targets
```
