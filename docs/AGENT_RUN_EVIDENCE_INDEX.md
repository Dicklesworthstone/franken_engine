# Agent Run Evidence Index

Bead: `bd-es4nn`

`scripts/agent_run_evidence_index.sh` builds a deterministic,
fixture-fed index for one agent run. It reuses
`scripts/swarm_agent_causal_trace_normalizer.sh` and
`scripts/swarm_agent_causal_trace_graph.sh`, then adds explicit complete-run
checks for matching bead state, closeout commit evidence, validation command
transcripts, and RCH run manifest or artifact bundle hashes.

The index is proof-only and advisory-only. It does not query live Agent Mail,
run Cargo, invoke rch, mutate br, release reservations, send mail, change queue
policy, or mutate workers.

## Input

The script accepts one preserved snapshot:

```bash
./scripts/agent_run_evidence_index.sh \
  --run-snapshot-json artifacts/agent-run-snapshot.json \
  --output-dir /tmp/agent-run-evidence-index
```

The snapshot embeds the same source shapes consumed by the causal trace
normalizer:

- `br_issue_json`
- `agent_mail_profiles_json`
- `agent_mail_messages_json`
- `git_closeout_commits_json`
- `rch_validation_artifacts_json`
- `validation_commands_json`
- optional reservation, write-set, `br`, `bv`, git status, and operator-status
  snapshots

Missing Agent Mail snapshots become degraded edges instead of silent omissions.
For snapshots marked `complete_run_expected: true`, missing bead, commit,
command transcript, or RCH manifest evidence fails closed.

## Artifacts

- `agent_run_evidence_index.json`
- `index_edges.jsonl`
- `causal_trace_normalizer/swarm_agent_causal_trace_events.json`
- `causal_trace_graph/swarm_agent_causal_trace_graph.json`
- `events.jsonl`
- `commands.txt`
- `report.md`

## Validation

```bash
jq empty docs/agent_run_evidence_index_contract_v1.json scripts/testdata/agent_run_evidence_index/cases.json
bash -n scripts/agent_run_evidence_index.sh scripts/e2e/agent_run_evidence_index_smoke.sh
shellcheck -x scripts/agent_run_evidence_index.sh scripts/e2e/agent_run_evidence_index_smoke.sh
bash scripts/e2e/agent_run_evidence_index_smoke.sh check
bash scripts/e2e/agent_run_evidence_index_smoke.sh selftest
bash scripts/e2e/swarm_agent_causal_trace_graph_smoke.sh check
git diff --check -- scripts/agent_run_evidence_index.sh scripts/e2e/agent_run_evidence_index_smoke.sh scripts/testdata/agent_run_evidence_index/cases.json docs/agent_run_evidence_index_contract_v1.json docs/AGENT_RUN_EVIDENCE_INDEX.md
```
