#!/usr/bin/env bash
set -euo pipefail

root_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
gate="${root_dir}/scripts/idea_wizard_iv_operator_status_truth_gate.sh"
replay="${root_dir}/scripts/e2e/idea_wizard_iv_operator_status_truth_gate_replay.sh"
mode="${1:-check}"

record_pass() { printf 'PASS idea-wizard-iv-operator-truth-gate %s\n' "$1"; }
record_failure() { printf 'FAIL idea-wizard-iv-operator-truth-gate %s\n' "$1" >&2; exit 1; }

write_saturation_report() {
  local path="$1"
  cat >"$path" <<'JSON'
{
  "schema_version": "franken-engine.idea-wizard-iv-zero-ready-saturation-report.v1",
  "decision": "degraded",
  "classification": "coordination_degraded",
  "br_ready_count": 0,
  "child_reports": [
    {"surface_id":"closed_bead_proof_integrity","decision":"green"},
    {"surface_id":"coordination_health_packet","decision":"degraded"},
    {"surface_id":"validation_impact_plan","decision":"degraded"},
    {"surface_id":"resource_proof_heatmap","decision":"green"}
  ]
}
JSON
}

write_doc() {
  local case_id="$1"
  local path="$2"
  case "$case_id" in
    safe)
      cat >"$path" <<'EOF'
The IW4 saturation control plane is advisory and proof-only. Green status
requires the required artifacts from the replay bundle. Heavy validation is
RCH-backed with `rch exec -- env CARGO_TARGET_DIR=`. Degraded coordination and
Agent Mail degraded states are limitations; the gate does not repair Agent Mail
or mutate beads.
EOF
      ;;
    forbidden)
      cat >"$path" <<'EOF'
This production guarantee automatically repairs Agent Mail and proves project-wide completion.
EOF
      ;;
    missing-required)
      cat >"$path" <<'EOF'
The status report shows a queue summary.
EOF
      ;;
  esac
}

run_case() {
  local case_id="$1"
  local expected_decision="$2"
  local expected_status="$3"
  local tmpdir output_dir status
  tmpdir="$(mktemp -d)"
  output_dir="${tmpdir}/out"
  write_saturation_report "${tmpdir}/saturation.json"
  write_doc "$case_id" "${tmpdir}/operator.md"
  set +e
  IDEA_WIZARD_IV_OPERATOR_TRUTH_GATE_GENERATED_AT_UTC="2026-05-11T00:00:00Z" \
    "$gate" \
    --saturation-report-json "${tmpdir}/saturation.json" \
    --operator-doc "${tmpdir}/operator.md" \
    --source-revision "smoke-${case_id}" \
    --output-dir "$output_dir" >"${tmpdir}/stdout.log" 2>"${tmpdir}/stderr.log"
  status=$?
  set -e
  if [[ "$status" -ne "$expected_status" ]]; then
    cat "${tmpdir}/stderr.log" >&2
    record_failure "unexpected exit for ${case_id}: got ${status}, expected ${expected_status}"
  fi
  [[ -f "${output_dir}/operator_truth_gate_report.json" ]] || record_failure "missing truth report for ${case_id}"
  [[ -f "${output_dir}/operator_status.md" ]] || record_failure "missing operator status for ${case_id}"
  jq -e --arg decision "$expected_decision" '.decision == $decision' "${output_dir}/operator_truth_gate_report.json" >/dev/null \
    || record_failure "decision mismatch for ${case_id}"
  "$replay" --bundle-dir "$output_dir" >/dev/null \
    || record_failure "replay failed for ${case_id}"
  if [[ "$case_id" == "safe" ]]; then
    grep -Fq 'Advisory only' "${output_dir}/operator_status.md" || record_failure "safe status missing pasteable advisory"
  fi
  record_pass "$case_id"
}

run_replay_missing_case() {
  local tmpdir
  tmpdir="$(mktemp -d)"
  if "$replay" --bundle-dir "$tmpdir" >/dev/null 2>&1; then
    record_failure "replay accepted missing bundle"
  fi
  record_pass "replay-missing-bundle"
}

run_check() {
  bash -n "$gate" "$replay" "${BASH_SOURCE[0]}"
  run_case safe degraded 0
  run_case forbidden fail_closed 42
  run_case missing-required fail_closed 42
  run_replay_missing_case
  git -C "$root_dir" diff --check -- \
    docs/IDEA_WIZARD_IV_OPERATOR_STATUS_TRUTH_GATE.md \
    scripts/idea_wizard_iv_operator_status_truth_gate.sh \
    scripts/e2e/idea_wizard_iv_operator_status_truth_gate_replay.sh \
    scripts/e2e/idea_wizard_iv_operator_status_truth_gate_smoke.sh \
    docs/idea_wizard_iv_saturation_convergence_v1.json
  record_pass "check"
}

case "$mode" in
  check) run_check ;;
  -h|--help|help) printf 'Usage: %s [check]\n' "${BASH_SOURCE[0]}" ;;
  *) printf 'unknown mode: %s\n' "$mode" >&2; exit 64 ;;
esac
