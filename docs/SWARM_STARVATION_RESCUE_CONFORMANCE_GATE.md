# SWARM Starvation Rescue Conformance Gate

`scripts/swarm_starvation_rescue_conformance_gate.sh` checks that a starvation
rescue planner receipt stays ownership-safe, fairness-honest, and artifact
grounded before any operator treats it as an actionable rescue advisory.

The gate is report-only. It does not reopen beads, exchange leases, or change
worker state. Its job is to prove that the planner result is still truthful
with respect to the normalized rescue input, the approved scenario matrix, and
the drill command transcripts behind that policy surface.

## Inputs

Required:

- `--starvation-rescue-plan-json FILE`

The gate resolves the upstream inputs from the planner receipt itself:

- `starvation_rescue_input_json`
- `scenario_matrix_report_json`

## Verified invariants

The conformance report fails closed when any of these invariants drift:

1. Contradictory ownership must force a `fail_closed` planner decision and a
   cited `contradictory_ownership` reason.
2. Stale-lock uncertainty (`contact_first_count > 0`) must block advisory
   rescue and preserve a `contact_owner_before_exchange` recommendation.
3. Salvage-pinned or manual-review truth must block advisory rescue and
   preserve a `preserve_pinned_evidence` recommendation.
4. Degraded-rch transport truth (`local_rch_fallback_detected`) must force
   `fail_closed`, keep the `local_fallback` scenario class, and cite
   `local_rch_fallback_admitted`.
5. Planner claims must resolve back to real artifact paths and real matched
   scenario-matrix case receipts.
6. Drill transcripts must not contain bare cargo or bare heavy Cargo examples;
   all heavy commands in drill evidence must stay `rch`-backed.
7. The normalized rescue input must stay fresh enough for the chosen
   `--stale-after-seconds` threshold.

## Outputs

The gate writes:

- `swarm_starvation_rescue_conformance_report.json`
- `events.jsonl`
- `commands.txt`
- `report.md`

Exit codes:

- `0`: report emitted without conformance failures
- `42`: fail-closed because ownership, freshness, artifact lineage, or drill
  transcript truth drifted
- `64`: invalid or missing input

## Validation

```bash
bash -n scripts/swarm_starvation_rescue_conformance_gate.sh
bash -n scripts/e2e/swarm_starvation_rescue_conformance_gate_smoke.sh
shellcheck -x scripts/swarm_starvation_rescue_conformance_gate.sh scripts/e2e/swarm_starvation_rescue_conformance_gate_smoke.sh
jq empty docs/swarm_starvation_rescue_conformance_gate_contract_v1.json
bash scripts/e2e/swarm_starvation_rescue_conformance_gate_smoke.sh check
bash scripts/e2e/swarm_starvation_rescue_conformance_gate_smoke.sh selftest
```

This surface is intentionally narrower than the eventual SWARM-CTRL-X runbook
truth gate. It proves the planner receipt is still honest; later operator
surfaces can build on that receipt instead of re-deriving ownership and rescue
fairness rules from scratch.
