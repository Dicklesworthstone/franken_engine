#!/usr/bin/env bash
set -euo pipefail

root_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
default_runbook="${root_dir}/docs/SWARM_CTRL_XVII_OPERATOR_RUNBOOK.md"
default_contract="${root_dir}/docs/swarm_ctrl_xvii_runbook_truth_contract_v1.json"
artifact_root="${SWARM_CONTROL_SURFACE_CATALOG_TRUTH_ROOT:-${TMPDIR:-/tmp}/franken-engine-swarm-control-surface-truth}"
run_id="${SWARM_CONTROL_SURFACE_CATALOG_TRUTH_RUN_ID:-$(date -u +%Y%m%dT%H%M%SZ)}"
run_dir="${SWARM_CONTROL_SURFACE_CATALOG_TRUTH_RUN_DIR:-${artifact_root}/${run_id}}"

mode="check"
runbook_md="$default_runbook"
contract_json="$default_contract"

if [[ "$#" -gt 0 && "$1" != --* ]]; then
  mode="$1"
  shift
fi

usage() {
  cat >&2 <<'EOF'
Usage: ./scripts/e2e/swarm_control_surface_catalog_runbook_truth_gate.sh [check|selftest] [OPTIONS]

Options:
  --runbook-md FILE
  --contract-json FILE
  --output-dir DIR
EOF
}

while [[ "$#" -gt 0 ]]; do
  case "$1" in
    --runbook-md)
      runbook_md="${2:-}"
      shift 2
      ;;
    --contract-json)
      contract_json="${2:-}"
      shift 2
      ;;
    --output-dir)
      run_dir="${2:-}"
      shift 2
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      printf 'unknown argument: %s\n' "$1" >&2
      usage
      exit 64
      ;;
  esac
done

record_pass() {
  printf 'PASS swarm-control-surface-catalog-truth-gate %s\n' "$1"
}

record_failure() {
  printf 'FAIL swarm-control-surface-catalog-truth-gate %s\n' "$1" >&2
  exit 1
}

write_report() {
  local decision="$1"
  local reason="$2"
  mkdir -p "$run_dir"
  # shellcheck disable=SC2094
  jq -n \
    --arg schema_version "franken-engine.swarm-control-surface-catalog-runbook-truth-report.v1" \
    --arg decision "$decision" \
    --arg reason "$reason" \
    --arg runbook_md "$runbook_md" \
    --arg contract_json "$contract_json" \
    --arg report_json "${run_dir}/runbook_truth_report.json" \
    --arg commands_txt "${run_dir}/commands.txt" \
    --arg report_md "${run_dir}/report.md" \
    '{
      schema_version:$schema_version,
      decision:$decision,
      reason:$reason,
      runbook_md:$runbook_md,
      contract_json:$contract_json,
      artifact_paths:{
        runbook_truth_report_json:$report_json,
        commands_txt:$commands_txt,
        report_md:$report_md
      },
      mutation_policy:{
        advisory_only:true,
        proof_only:true,
        fixture_fed_only:true,
        mutates_br:false,
        queries_live_agent_mail:false,
        sends_agent_mail:false,
        releases_reservations:false,
        runs_cargo:false,
        runs_rch:false,
        changes_live_queue_policy:false,
        replaces_operator_status_report:false
      }
    }' >"${run_dir}/runbook_truth_report.json"
  printf './scripts/e2e/swarm_control_surface_catalog_runbook_truth_gate.sh check --runbook-md %q --contract-json %q\n' "$runbook_md" "$contract_json" >"${run_dir}/commands.txt"
  {
    printf '# Swarm Control-Surface Catalog Runbook Truth Gate\n\n'
    printf -- "- decision: \`%s\`\n" "$decision"
    printf -- "- reason: \`%s\`\n" "$reason"
  } >"${run_dir}/report.md"
}

run_gate_files() {
  local runbook_path="$1"
  local contract_path="$2"

  if [[ ! -f "$runbook_path" ]]; then
    printf 'missing runbook: %s\n' "$runbook_path" >&2
    return 64
  fi
  if [[ ! -f "$contract_path" ]]; then
    printf 'missing truth contract: %s\n' "$contract_path" >&2
    return 64
  fi
  if ! jq empty "$contract_path" >/dev/null; then
    printf 'invalid truth contract JSON: %s\n' "$contract_path" >&2
    return 64
  fi

  jq -e '
    .schema_version == "franken-engine.swarm-ctrl-xvii-runbook-truth-contract.v1"
    and (.required_denials | index("does not mutate br"))
    and (.required_denials | index("does not query live Agent Mail"))
    and (.required_denials | index("does not send Agent Mail"))
    and (.required_denials | index("does not release reservations"))
    and (.required_denials | index("does not run Cargo"))
    and (.required_denials | index("does not run RCH"))
    and (.required_denials | index("does not change queue policy"))
    and (.required_denials | index("does not replace operator status"))
  ' "$contract_path" >/dev/null || return 42

  local required
  while IFS= read -r required; do
    grep -Fq "$required" "$runbook_path" || return 42
  done < <(jq -r '.required_denials[]' "$contract_path")

  grep -Fq 'scripts/swarm_operator_status_report.sh remains the only operator-status producer.' "$runbook_path" || return 42
  grep -Fq 'The drill uses the real catalog normalizer, intent router, drift gate, intake guard, and operator status reporter.' "$runbook_path" || return 42

  if grep -Eiq '(^|[^[:alpha:]])(mutates br|queries live Agent Mail|sends Agent Mail|releases reservations|runs Cargo|runs RCH|changes queue policy|replaces operator status|automatic remediation|second dashboard producer)([^[:alpha:]]|$)' "$runbook_path"; then
    return 42
  fi
}

run_check() {
  local status
  bash -n "${BASH_SOURCE[0]}"

  set +e
  run_gate_files "$runbook_md" "$contract_json"
  status=$?
  set -e

  if [[ "$status" -ne 0 ]]; then
    write_report "fail_closed" "runbook truth gate rejected claims"
    return "$status"
  fi

  write_report "pass" "runbook truth claims are bounded and advisory-only"
  jq empty "${run_dir}/runbook_truth_report.json"
  record_pass "check"
  printf 'swarm_control_surface_catalog_runbook_truth_report=%s\n' "${run_dir}/runbook_truth_report.json"
}

run_selftest() {
  local tmp_root bad_runbook bad_contract status
  run_check

  tmp_root="${run_dir}/selftest"
  mkdir -p "$tmp_root"
  bad_runbook="${tmp_root}/bad_runbook.md"
  bad_contract="${tmp_root}/bad_contract.json"

  cp "$contract_json" "$bad_contract"
  {
    printf '# Bad Runbook\n\n'
    printf 'This catalog mutates br, queries live Agent Mail, sends Agent Mail, releases reservations, runs Cargo, runs RCH, changes queue policy, replaces operator status, and performs automatic remediation.\n'
  } >"$bad_runbook"

  set +e
  run_gate_files "$bad_runbook" "$bad_contract"
  status=$?
  set -e
  if [[ "$status" -eq 0 ]]; then
    record_failure "selftest accepted forbidden runbook claims"
  fi

  jq 'del(.required_denials[])' "$contract_json" >"${tmp_root}/missing_denial_contract.json"
  set +e
  run_gate_files "$runbook_md" "${tmp_root}/missing_denial_contract.json"
  status=$?
  set -e
  if [[ "$status" -eq 0 ]]; then
    record_failure "selftest accepted malformed truth contract"
  fi

  record_pass "selftest"
}

case "$mode" in
  check)
    run_check
    ;;
  selftest)
    run_selftest
    ;;
  -h|--help|help)
    usage
    ;;
  *)
    usage
    record_failure "unknown mode: ${mode}"
    ;;
esac
