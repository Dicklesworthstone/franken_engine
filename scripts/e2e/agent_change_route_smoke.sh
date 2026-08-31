#!/usr/bin/env bash
set -euo pipefail

root_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
work_dir="${TMPDIR:-/tmp}/franken_engine_agent_route_smoke_${$}"
mkdir -p "$work_dir"

python3 "${root_dir}/scripts/agent_route.py" --root "$root_dir" --check

python3 "${root_dir}/scripts/agent_route.py" \
  --root "$root_dir" \
  --path crates/franken-engine/src/lowering_pipeline.rs \
  --format json \
  --strict >"${work_dir}/lowering.json"

python3 - "${work_dir}/lowering.json" <<'PY'
import json
import sys
payload = json.load(open(sys.argv[1], encoding="utf-8"))
assert payload["unmatched_paths"] == []
assert payload["path_routes"][0]["primary_route"] == "lowering-ir"
route = next(item for item in payload["routes"] if item["route_id"] == "lowering-ir")
assert route["hotspot"]["level"] == "critical"
assert "docs/LOWERING_PIPELINE_CONTRACT.md" in payload["read_first"]
assert "./scripts/run_lowering_gap_truth_invariant.sh ci" in payload["focused_commands"]
assert "docs/claim_to_proof_matrix_v1.json" in payload["downstream_artifacts"]
PY

python3 "${root_dir}/scripts/agent_route.py" \
  --root "$root_dir" \
  --path scripts/red_team_compromise_rate_metric.py \
  --format json \
  --strict >"${work_dir}/evidence.json"

python3 - "${work_dir}/evidence.json" <<'PY'
import json
import sys
payload = json.load(open(sys.argv[1], encoding="utf-8"))
assert payload["path_routes"][0]["primary_route"] == "claim-evidence"
matched = {item["route_id"] for item in payload["path_routes"][0]["matches"]}
assert {"claim-evidence", "cli-operator"} <= matched
assert "FE-CLAIM-011" in payload["claim_ids"]
assert "bash scripts/e2e/red_team_compromise_rate_metric_comparator_smoke.sh" in payload["focused_commands"]
PY

set +e
python3 "${root_dir}/scripts/agent_route.py" \
  --root "$root_dir" \
  --path totally/unmapped/new_surface.xyz \
  --strict >"${work_dir}/unmapped.txt" 2>"${work_dir}/unmapped.err"
unmapped_rc=$?
set -e
if [[ "$unmapped_rc" -ne 2 ]]; then
  echo "strict unmapped-path drill returned ${unmapped_rc}, expected 2" >&2
  exit 1
fi
grep -q "UNROUTED" "${work_dir}/unmapped.txt"

cp "${root_dir}/docs/agent_change_routes_v1.json" "${work_dir}/invalid.json"
python3 - "${work_dir}/invalid.json" <<'PY'
import json
import sys
path = sys.argv[1]
payload = json.load(open(path, encoding="utf-8"))
payload["routes"][0]["neighbors"].append("route-that-does-not-exist")
with open(path, "w", encoding="utf-8") as handle:
    json.dump(payload, handle)
PY

set +e
python3 "${root_dir}/scripts/agent_route.py" \
  --root "$root_dir" \
  --manifest "${work_dir}/invalid.json" \
  --check >"${work_dir}/invalid.out" 2>"${work_dir}/invalid.err"
invalid_rc=$?
set -e
if [[ "$invalid_rc" -eq 0 ]]; then
  echo "invalid-neighbor drill unexpectedly passed" >&2
  exit 1
fi
grep -q "unknown route 'route-that-does-not-exist'" "${work_dir}/invalid.err"

printf 'agent change-route smoke passed; artifacts=%s\n' "$work_dir"
