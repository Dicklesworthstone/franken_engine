#!/usr/bin/env bash
set -euo pipefail

root_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
default_runbook="${root_dir}/docs/IDEA_WIZARD_III_OPERATOR_WORKFLOW.md"
default_contract="${root_dir}/docs/idea_wizard_iii_operator_runbook_truth_contract_v1.json"
golden_dir="${IDEA_WIZARD_III_TRUTH_GATE_GOLDEN_DIR:-${root_dir}/scripts/testdata/goldens}"
artifact_root="${IDEA_WIZARD_III_TRUTH_GATE_ROOT:-${TMPDIR:-/tmp}/franken-engine-idea-wizard-iii-truth-gate}"
run_id="${IDEA_WIZARD_III_TRUTH_GATE_RUN_ID:-$(date -u +%Y%m%dT%H%M%SZ)-$$}"
run_dir="${IDEA_WIZARD_III_TRUTH_GATE_RUN_DIR:-${artifact_root}/${run_id}}"

mode="check"
runbook_md="$default_runbook"
contract_json="$default_contract"

if [[ "$#" -gt 0 && "$1" != --* ]]; then
  mode="$1"
  shift
fi

usage() {
  cat >&2 <<'EOF'
Usage: ./scripts/e2e/idea_wizard_iii_operator_runbook_truth_gate.sh [check|selftest] [OPTIONS]

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
  printf 'PASS idea-wizard-iii-operator-truth %s\n' "$1"
}

record_failure() {
  printf 'FAIL idea-wizard-iii-operator-truth %s\n' "$1" >&2
}

write_report() {
  local decision="$1"
  local reason="$2"
  mkdir -p "$run_dir"
  # shellcheck disable=SC2094 # The output path is embedded as report data; jq does not read it.
  jq -n \
    --arg schema_version "franken-engine.idea-wizard-iii-operator-truth-report.v1" \
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
      artifacts:{
        runbook_truth_report_json:$report_json,
        commands_txt:$commands_txt,
        report_md:$report_md
      },
      mutation_policy:{
        advisory_only:true,
        proof_only:true,
        fixture_fed_only:true,
        mutates_live_queues:false,
        mutates_br:false,
        sends_agent_mail:false,
        repairs_agent_mail_db:false,
        runs_cargo:false,
        runs_rch:false,
        mutates_remote_workers:false,
        deletes_or_overwrites_target_dirs:false
      }
    }' >"${run_dir}/runbook_truth_report.json"
  printf './scripts/e2e/idea_wizard_iii_operator_runbook_truth_gate.sh check --runbook-md %q --contract-json %q\n' "$runbook_md" "$contract_json" >"${run_dir}/commands.txt"
  {
    printf '# IDEA-WIZARD-III Operator Truth Gate\n\n'
    printf -- "- decision: \`%s\`\n" "$decision"
    printf -- "- reason: \`%s\`\n" "$reason"
  } >"${run_dir}/report.md"
}

canonicalize_report() {
  local report_path="$1"
  local scrub_root="$2"

  jq -S --arg repo_root "$root_dir" --arg scrub_root "$scrub_root" '
    def scrub:
      if type == "object" then
        with_entries(.value |= scrub)
      elif type == "array" then
        map(scrub)
      elif type == "string" then
        split($repo_root) | join("[REPO_ROOT]")
        | split($scrub_root) | join("[SMOKE_ROOT]")
      else
        .
      end;
    scrub
  ' "$report_path"
}

assert_report_golden() {
  local golden_name="$1"
  local report_path="$2"
  local scrub_root="$3"
  local actual_path="${scrub_root}/${golden_name}.actual.golden"
  local golden_path="${golden_dir}/idea_wizard_iii_operator_truth_${golden_name}.golden"

  canonicalize_report "$report_path" "$scrub_root" >"$actual_path"
  if [[ "${UPDATE_GOLDENS:-0}" == "1" ]]; then
    mkdir -p "$golden_dir"
    cp "$actual_path" "$golden_path"
    record_pass "updated golden ${golden_name}"
    return
  fi
  if [[ ! -f "$golden_path" ]]; then
    record_failure "missing golden ${golden_path}"
    return 1
  fi
  if ! diff -u "$golden_path" "$actual_path"; then
    record_failure "golden drift ${golden_name}; set UPDATE_GOLDENS=1 only after reviewing the diff"
    return 1
  fi
  record_pass "golden matches ${golden_name}"
}

assert_no_forbidden_live_claims() {
  local doc_path="$1"
  local forbidden_lines

  forbidden_lines="$(grep -Ein \
    'mutates? live queues|mutates? br|claims beads|closes beads|reopens beads|reassigns beads|sends Agent Mail|repairs Agent Mail|automatic Agent Mail repair|runs? local heavy Cargo|local heavy Cargo validation|runs? cargo (check|test|clippy|build|bench)|starts? rch|runs? rch|mutates? remote workers|deletes target directories|overwrites target directories' \
    "$doc_path" \
    | grep -Eiv 'does not|must not|never|cannot|forbidden|reject|rejects|false|not green proof|advisory-only|proof-only|outside this artifact' || true)"
  if [[ -n "$forbidden_lines" ]]; then
    printf '%s\n' "$forbidden_lines" >&2
    return 42
  fi
}

assert_rch_wrapped_heavy_cargo_examples() {
  local doc_path="$1"
  local bare_cargo_lines

  bare_cargo_lines="$(grep -En '(^|[[:space:]])cargo (check|test|clippy|build|bench)' "$doc_path" \
    | grep -Ev 'rch exec -- env .*CARGO_TARGET_DIR=' || true)"
  if [[ -n "$bare_cargo_lines" ]]; then
    printf '%s\n' "$bare_cargo_lines" >&2
    return 42
  fi
}

assert_contract_shape() {
  local contract_path="$1"

  jq -e '
    .schema_version == "franken-engine.idea-wizard-iii-operator-runbook-truth-contract.v1"
    and .bead_id == "bd-99t7y"
    and .surface_id == "idea_wizard_iii_operator_truth_gate"
    and (.required_denials | type == "array")
    and ((.required_denials | length) >= 8)
    and (.referenced_contracts | type == "array")
    and ((.referenced_contracts | length) >= 1)
    and (.required_denials | index("does not mutate live queues") != null)
    and (.required_denials | index("does not repair the Agent Mail database") != null)
    and (.required_denials | index("does not run local heavy Cargo validation") != null)
    and (.required_denials | index("does not start `rch`") != null)
    and .mutation_policy.advisory_only == true
    and .mutation_policy.fixture_fed_only == true
    and .mutation_policy.mutates_live_queues == false
    and .mutation_policy.repairs_agent_mail_db == false
    and .mutation_policy.runs_cargo == false
    and .mutation_policy.runs_rch == false
  ' "$contract_path" >/dev/null
}

assert_referenced_contracts() {
  local contract_path="$1"
  local rel_path abs_path

  while IFS= read -r rel_path; do
    [[ -n "$rel_path" ]] || continue
    abs_path="${root_dir}/${rel_path}"
    if [[ ! -f "$abs_path" ]]; then
      printf 'missing referenced contract: %s\n' "$rel_path" >&2
      return 42
    fi
    jq empty "$abs_path" >/dev/null
  done < <(jq -r '.referenced_contracts[].path' "$contract_path")
}

run_gate_files() {
  local runbook_path="$1"
  local contract_path="$2"
  local required

  if [[ ! -f "$runbook_path" ]]; then
    printf 'missing runbook: %s\n' "$runbook_path" >&2
    return 64
  fi
  if [[ ! -f "$contract_path" ]]; then
    printf 'missing truth contract: %s\n' "$contract_path" >&2
    return 64
  fi
  jq empty "$contract_path" >/dev/null
  assert_contract_shape "$contract_path" || return 42
  assert_referenced_contracts "$contract_path" || return 42

  while IFS= read -r required; do
    [[ -n "$required" ]] || continue
    grep -Fq "$required" "$runbook_path" || {
      printf 'runbook missing required denial: %s\n' "$required" >&2
      return 42
    }
  done < <(jq -r '.required_denials[]' "$contract_path")

  grep -Fq './scripts/e2e/idea_wizard_iii_operator_runbook_truth_gate.sh check' "$runbook_path" || return 42
  grep -Fq './scripts/e2e/idea_wizard_iii_operator_runbook_truth_gate.sh selftest' "$runbook_path" || return 42
  grep -Fq 'PRESERVED_BUNDLE=' "$runbook_path" || return 42
  grep -Fq 'HIGH_CORE_VALIDATION_PRESSURE_FIXTURES=' "$runbook_path" || return 42
  grep -Fq 'SWARM_HANDOFF_CAPSULE_FIXTURES=' "$runbook_path" || return 42
  grep -Fq 'br ready --json' "$runbook_path" || return 42
  grep -Fq 'bv --recipe actionable --robot-plan' "$runbook_path" || return 42
  grep -Fq 'RCH_PRIORITY=low RCH_VISIBILITY=summary rch exec -- env' "$runbook_path" || return 42
  grep -Fq 'CARGO_TARGET_DIR=' "$runbook_path" || return 42

  assert_no_forbidden_live_claims "$runbook_path" || return 42
  assert_rch_wrapped_heavy_cargo_examples "$runbook_path" || return 42
}

run_check() {
  local status

  bash -n "${BASH_SOURCE[0]}"
  set +e
  run_gate_files "$runbook_md" "$contract_json"
  status=$?
  set -e
  if [[ "$status" -ne 0 ]]; then
    write_report "fail_closed" "runbook truth gate rejected docs or contract"
    return "$status"
  fi
  write_report "pass" "runbook docs and help examples are bounded and RCH-wrapped"
  jq empty "${run_dir}/runbook_truth_report.json"
  if [[ "$runbook_md" == "$default_runbook" && "$contract_json" == "$default_contract" ]]; then
    assert_report_golden "pass" "${run_dir}/runbook_truth_report.json" "$run_dir"
  fi
  record_pass "check"
  printf 'idea_wizard_iii_operator_truth_report=%s\n' "${run_dir}/runbook_truth_report.json"
}

run_selftest() {
  local tmp_root bad_live_doc missing_preserved_doc bad_contract status

  run_check
  tmp_root="${run_dir}/selftest"
  mkdir -p "$tmp_root"

  bad_live_doc="${tmp_root}/bad-live.md"
  cp "$runbook_md" "$bad_live_doc"
  printf '\nThis workflow mutates live queues, repairs Agent Mail, sends Agent Mail, mutates remote workers, and runs cargo test locally.\n' >>"$bad_live_doc"
  set +e
  bash "${BASH_SOURCE[0]}" check --runbook-md "$bad_live_doc" --contract-json "$contract_json" --output-dir "${tmp_root}/bad-live-out" >/dev/null 2>&1
  status=$?
  set -e
  if [[ "$status" -eq 0 ]]; then
    record_failure "selftest accepted forbidden live mutation and local Cargo claims"
    return 1
  fi
  assert_report_golden "fail_closed_bad_live" "${tmp_root}/bad-live-out/runbook_truth_report.json" "$tmp_root"
  record_pass "forbidden live mutation rejection"

  missing_preserved_doc="${tmp_root}/missing-preserved.md"
  grep -Fv 'PRESERVED_BUNDLE=' "$runbook_md" >"$missing_preserved_doc"
  set +e
  bash "${BASH_SOURCE[0]}" check --runbook-md "$missing_preserved_doc" --contract-json "$contract_json" --output-dir "${tmp_root}/missing-preserved-out" >/dev/null 2>&1
  status=$?
  set -e
  if [[ "$status" -eq 0 ]]; then
    record_failure "selftest accepted missing preserved-bundle replay command"
    return 1
  fi
  record_pass "missing preserved-bundle replay rejection"

  bad_contract="${tmp_root}/bad-contract.json"
  jq 'del(.required_denials)' "$contract_json" >"$bad_contract"
  set +e
  bash "${BASH_SOURCE[0]}" check --runbook-md "$runbook_md" --contract-json "$bad_contract" --output-dir "${tmp_root}/bad-contract-out" >/dev/null 2>&1
  status=$?
  set -e
  if [[ "$status" -eq 0 ]]; then
    record_failure "selftest accepted malformed truth contract"
    return 1
  fi
  record_pass "malformed truth contract rejection"

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
    exit 64
    ;;
esac
