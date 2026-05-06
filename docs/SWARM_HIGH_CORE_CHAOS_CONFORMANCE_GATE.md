# SWARM High-Core Chaos Conformance Gate

`scripts/swarm_high_core_chaos_conformance_gate.sh` verifies that the reviewed
SWARM-CTRL-IX high-core scenarios satisfy the calibrated threshold contract.

It is a conformance/report surface, not a new fault-injection engine. The gate
replays the existing scenario-matrix evidence, checks the threshold receipt and
forecast freshness, and emits a compliance matrix suitable for operator review.

## Inputs

Required:

- `--scenario-matrix-report-json`
- `--threshold-receipt-json`
- `--capacity-forecast-json`

Compatibility surfaces:

- `franken-engine.swarm-high-core-scenario-matrix-report.v1`
- `franken-engine.swarm-slo-threshold-receipt.v1`
- `franken-engine.swarm-capacity-forecast.v1`

The gate expects the matrix report to live beside its raw `cases/` directory so
it can inspect the reviewed command transcripts and per-case snapshot artifacts.

## Output

- `swarm_high_core_chaos_conformance_report.json`
- `events.jsonl`
- `commands.txt`
- `report.md`

The machine-readable report schema is
`franken-engine.swarm-high-core-chaos-conformance-report.v1`.

## Conformance Matrix

The gate emits one row per:

- SLO claim family
- scenario class

Rows carry:

- `requirement_level`: `MUST/SHOULD/MAY`
- `verdict`: `pass`, `fail`, or `expected_fail`
- `reason`
- explicit evidence source paths
- content hashes for the matrix report, threshold receipt, and forecast

`expected_fail` rows are reserved for intentionally advisory or unsupported
surfaces and must be mirrored into the documented deviations section of the
markdown report.

## Fail-Closed Rules

The gate exits `42` when it finds:

- missing or malformed required evidence
- scenario matrix drift or mismatches
- a fail-closed threshold receipt
- stale SWARM-CTRL-VIII capacity forecast artifacts
- bare Cargo commands in the reviewed high-core evidence transcripts
- unexpected local or unknown traceability outside the intentional
  degraded-worker fallback scenario
- any failing conformance row

## Truth Constraints

- The gate must remain fixture-fed and report-only.
- Bare Cargo commands are never acceptable evidence for this surface.
- The intentional degraded-worker fallback scenario is the only row family
  allowed to carry local or unknown traceability without tripping a gate-level
  fail-closed error.
- Archive and non-proof-cache ROI gaps must stay documented as
  `expected_fail` deviations instead of being silently treated as conformant.

## Validation

```bash
bash -n scripts/swarm_high_core_chaos_conformance_gate.sh
bash -n scripts/e2e/swarm_high_core_chaos_conformance_gate_smoke.sh
shellcheck -x scripts/swarm_high_core_chaos_conformance_gate.sh scripts/e2e/swarm_high_core_chaos_conformance_gate_smoke.sh
./scripts/e2e/swarm_high_core_chaos_conformance_gate_smoke.sh check
./scripts/e2e/swarm_high_core_chaos_conformance_gate_smoke.sh selftest
jq empty docs/swarm_high_core_chaos_conformance_gate_contract_v1.json
```
