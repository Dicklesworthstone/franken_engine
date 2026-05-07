# SWARM_CONTROL_SURFACE_INTENT_ROUTER

`bd-gkzuc` adds the SWARM-CTRL-XVII intent router over the normalized
control-surface catalog. `bd-g3ffl` extends its operator language for the
SWARM-CTRL-XVIII remote-proof, proof-economy, warm-target, build-storm, and
worker-toolchain family. The router turns operator symptoms into ranked,
advisory-only surface recommendations so agents do not create duplicate control
planes or start from the wrong script.

The router is artifact-fed. It reads a normalized catalog plus an explicit
intent JSON document. It can optionally read bead-status and operator-constraint
snapshots, but it never queries live `br`, Agent Mail, git, RCH, Cargo, or
workers.

## Inputs

- `--catalog-json`: normalized `swarm_control_surface_catalog.json`
- `--intent-json`: operator intent with `intent_tags`, `symptom_tags`, and
  optional `operator_constraints`
- `--bead-status-json`: optional issue status snapshot
- `--operator-constraints-json`: optional external constraints such as
  `docs_only` or `no_live_queries`

## Routing

The router expands common operator phrases into canonical catalog tags, then
scores each catalog row by tag overlap:

- remote proof residency and artifact retrieval route toward resident
  remote-proof, artifact mirror, and archive export surfaces
- proof-cost pressure and reuse uncertainty route toward proof-economy policy
  and replay surfaces
- build-storm, QoS, and toolchain-pressure language routes toward worker
  capability/toolchain normalization when no complete build-storm catalog row is
  available
- sticky worker, warm-target ROI, and prefetch language route toward warm-target
  ROI and prefetch surfaces
- local-fallback contamination routes toward RCH rehabilitation or remote-proof
  surfaces instead of creating a duplicate proof lane

After expansion, scoring is deterministic:

- matching intent tag: 10 points
- matching symptom tag: 5 points

Rows with score zero are ignored. Recommendations are sorted by score descending
and `surface_id` ascending. The router emits the top ranked surfaces, matched
tags, advisory commands, artifacts to preserve, blocked or degraded reasons, and
duplicate-new-work warnings.

## Fail-Closed Rules

The router exits 42 when:

- no catalog surface matches the requested tags
- a matched row claims live mutation or automatic remediation
- a matched row has bare heavy Cargo in `validation_commands`
- a matched row is missing required catalog artifacts such as implementation
  script, smoke script, contract JSON, or emitted artifacts
- matched surfaces conflict on mutation policy

## Outputs

- `swarm_control_surface_intent_plan.json`
- `events.jsonl`
- `commands.txt`
- `report.md`

Commands are text only. Operators still decide whether to run them.

## Validation

```bash
jq empty scripts/testdata/swarm_control_surface_intent_router/cases.json
bash -n scripts/swarm_control_surface_intent_router.sh scripts/e2e/swarm_control_surface_intent_router_smoke.sh
shellcheck -x scripts/swarm_control_surface_intent_router.sh scripts/e2e/swarm_control_surface_intent_router_smoke.sh
bash scripts/e2e/swarm_control_surface_intent_router_smoke.sh check
bash scripts/e2e/swarm_control_surface_intent_router_smoke.sh selftest
git diff --check -- docs/SWARM_CONTROL_SURFACE_INTENT_ROUTER.md scripts/swarm_control_surface_intent_router.sh scripts/e2e/swarm_control_surface_intent_router_smoke.sh scripts/testdata/swarm_control_surface_intent_router/cases.json
```
