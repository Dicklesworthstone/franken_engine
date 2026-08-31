#!/usr/bin/env bash
set -euo pipefail

root_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
work_dir="${TMPDIR:-/tmp}/franken_engine_red_team_comparator_smoke_${$}"
bin_dir="${work_dir}/bin"
artifact_root="${work_dir}/artifacts"
mkdir -p "$bin_dir" "$artifact_root"

cat >"${bin_dir}/node" <<'NODE'
#!/usr/bin/env bash
set -euo pipefail
if [[ "${1:-}" == "--version" ]]; then
  echo "v-smoke-node"
  exit 0
fi
scenario="$(basename "$1" .js)"
printf '{"scenario":"%s","attack_succeeded":true}\n' "$scenario"
NODE

cat >"${bin_dir}/bun" <<'BUN'
#!/usr/bin/env bash
set -euo pipefail
if [[ "${1:-}" == "--version" ]]; then
  echo "v-smoke-bun"
  exit 0
fi
scenario="$(basename "${@: -1}" .js)"
if [[ "$scenario" == "prototype_pollution_capability_escape" ]]; then
  printf '{"scenario":"%s","attack_succeeded":false}\n' "$scenario"
  exit 1
fi
printf '{"scenario":"%s","attack_succeeded":true}\n' "$scenario"
BUN

cat >"${bin_dir}/frankenctl" <<'FRANKEN'
#!/usr/bin/env bash
set -euo pipefail
if [[ "${1:-}" == "--version" ]]; then
  echo "frankenctl-smoke 0.1.0"
  exit 0
fi
input=""
out=""
while (($#)); do
  case "$1" in
    --input)
      input="$2"
      shift 2
      ;;
    --out)
      out="$2"
      shift 2
      ;;
    *)
      shift
      ;;
  esac
done
scenario="$(basename "$input" .js)"
mkdir -p "$(dirname "$out")"
printf '{"scenario":"%s","attack_succeeded":false}\n' "$scenario" >"$out"
exit 1
FRANKEN

cat >"${bin_dir}/frankenctl-invalid" <<'INVALID'
#!/usr/bin/env bash
set -euo pipefail
if [[ "${1:-}" == "--version" ]]; then
  echo "frankenctl-smoke-invalid 0.1.0"
  exit 0
fi
echo "simulated runtime crash without an attack disposition" >&2
exit 2
INVALID

chmod +x "${bin_dir}/node" "${bin_dir}/bun" "${bin_dir}/frankenctl" "${bin_dir}/frankenctl-invalid"

NODE_BIN="${bin_dir}/node" \
BUN_BIN="${bin_dir}/bun" \
FRANKENENGINE_BIN="${bin_dir}/frankenctl" \
RED_TEAM_COMPROMISE_RATE_METRIC_ARTIFACT_ROOT="$artifact_root" \
RED_TEAM_COMPROMISE_RATE_METRIC_RUN_ID="executed-comparators" \
RED_TEAM_COMPROMISE_RATE_METRIC_CODE_REVISION="smoke-revision" \
  "${root_dir}/scripts/run_red_team_compromise_rate_metric_gate.sh" pass

pass_dir="${artifact_root}/executed-comparators"
jq -e '
  .decision == "pass"
  and .scenarios_total == 5
  and .baseline_compromise_millionths_node == 1000000
  and .baseline_compromise_millionths_bun == 800000
  and .compromise_millionths == 0
' "${pass_dir}/metric_report.json" >/dev/null
jq -s -e '
  length == 5
  and any(.[]; .bun_attacker_succeeded == false)
  and all(.[];
    .is_placeholder_data == false
    and (.runtime_receipts.node.transcript_hash | startswith("sha256:"))
    and (.runtime_receipts.bun.transcript_hash | startswith("sha256:"))
    and (.runtime_receipts.frankenengine.transcript_hash | startswith("sha256:"))
  )
' "${pass_dir}/scenarios.jsonl" >/dev/null

invalid_rc=0
NODE_BIN="${bin_dir}/node" \
BUN_BIN="${bin_dir}/bun" \
FRANKENENGINE_BIN="${bin_dir}/frankenctl-invalid" \
RED_TEAM_COMPROMISE_RATE_METRIC_ARTIFACT_ROOT="$artifact_root" \
RED_TEAM_COMPROMISE_RATE_METRIC_RUN_ID="invalid-franken-disposition" \
RED_TEAM_COMPROMISE_RATE_METRIC_CODE_REVISION="smoke-revision" \
  "${root_dir}/scripts/run_red_team_compromise_rate_metric_gate.sh" pass || invalid_rc=$?

if [[ "$invalid_rc" -eq 0 ]]; then
  echo "invalid FrankenEngine disposition unexpectedly passed" >&2
  exit 1
fi
invalid_dir="${artifact_root}/invalid-franken-disposition"
jq -e '
  .decision == "fail_closed"
  and .reason == "frankenengine_probe_invalid"
  and .blocker.placeholder_rows_emitted == false
' "${invalid_dir}/metric_report.json" >/dev/null
[[ ! -s "${invalid_dir}/scenarios.jsonl" ]]

printf 'red-team comparator smoke passed; artifacts=%s\n' "$work_dir"
