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
  local decision="${2:-degraded}"
  local classification="${3:-coordination_degraded}"
  local coordination="${4:-degraded}"
  cat >"$path" <<'JSON'
{
  "schema_version": "franken-engine.idea-wizard-iv-zero-ready-saturation-report.v1",
  "decision": "__DECISION__",
  "classification": "__CLASSIFICATION__",
  "br_ready_count": 0,
  "child_reports": [
    {"surface_id":"closed_bead_proof_integrity","decision":"green"},
    {"surface_id":"coordination_health_packet","decision":"__COORDINATION__"},
    {"surface_id":"validation_impact_plan","decision":"degraded"},
    {"surface_id":"resource_proof_heatmap","decision":"green"}
  ]
}
JSON
  sed -i \
    -e "s/__DECISION__/${decision}/g" \
    -e "s/__CLASSIFICATION__/${classification}/g" \
    -e "s/__COORDINATION__/${coordination}/g" \
    "$path"
}

write_closed_proof_report() {
  local case_id="$1"
  local path="$2"
  case "$case_id" in
    clean)
      cat >"$path" <<'JSON'
{
  "schema_version": "franken-engine.idea-wizard-iv-closed-bead-proof.v1",
  "decision": "green",
  "classification": "true_saturation",
  "weak_evidence_count": 0,
  "semantic_contradiction_count": 0
}
JSON
      ;;
    semantic)
      cat >"$path" <<'JSON'
{
  "schema_version": "franken-engine.idea-wizard-iv-closed-bead-proof.v1",
  "decision": "degraded",
  "classification": "semantic_contradiction",
  "weak_evidence_count": 1,
  "semantic_contradiction_count": 1
}
JSON
      ;;
    *)
      record_failure "unknown closed proof fixture ${case_id}"
      ;;
  esac
}

write_source_gap_report() {
  local case_id="$1"
  local path="$2"
  case "$case_id" in
    clean)
      cat >"$path" <<'JSON'
{
  "schema_version": "franken-engine.idea-wizard-xii-zero-ready-source-gap-picker.v1",
  "decision": "no_actionable_source_gap",
  "classification": "true_zero_ready_no_source_gaps",
  "proposal_count": 0,
  "proposed_beads": []
}
JSON
      ;;
    source-gap)
      cat >"$path" <<'JSON'
{
  "schema_version": "franken-engine.idea-wizard-xii-zero-ready-source-gap-picker.v1",
  "decision": "proposals_emitted",
  "classification": "source_gap_candidates",
  "proposal_count": 1,
  "proposed_beads": [
    {
      "title": "[IDEA-WIZARD-XII-C] Reopen real pending-promise await execution from source evidence",
      "priority": 1,
      "file": "crates/franken-core/src/baseline_interpreter.rs",
      "line": 5408
    }
  ]
}
JSON
      ;;
    *)
      record_failure "unknown source-gap fixture ${case_id}"
      ;;
  esac
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
  local zero_truth_case="${4:-missing}"
  local expected_zero_state="${5:-degraded_unknown}"
  local tmpdir output_dir status extra_args
  tmpdir="$(mktemp -d)"
  output_dir="${tmpdir}/out"
  write_saturation_report "${tmpdir}/saturation.json" "green" "true_saturation" "green"
  write_doc "$case_id" "${tmpdir}/operator.md"
  extra_args=()
  case "$zero_truth_case" in
    clean)
      write_closed_proof_report clean "${tmpdir}/closed.json"
      write_source_gap_report clean "${tmpdir}/source_gap.json"
      extra_args+=(--closed-bead-proof-json "${tmpdir}/closed.json" --source-gap-picker-json "${tmpdir}/source_gap.json")
      ;;
    source-gap)
      write_closed_proof_report semantic "${tmpdir}/closed.json"
      write_source_gap_report source-gap "${tmpdir}/source_gap.json"
      extra_args+=(--closed-bead-proof-json "${tmpdir}/closed.json" --source-gap-picker-json "${tmpdir}/source_gap.json")
      ;;
    missing)
      ;;
    *)
      record_failure "unknown zero truth case ${zero_truth_case}"
      ;;
  esac
  set +e
  IDEA_WIZARD_IV_OPERATOR_TRUTH_GATE_GENERATED_AT_UTC="2026-05-11T00:00:00Z" \
    "$gate" \
    --saturation-report-json "${tmpdir}/saturation.json" \
    "${extra_args[@]}" \
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
  jq -e --arg state "$expected_zero_state" '.zero_ready_truth.state == $state' "${output_dir}/operator_truth_gate_report.json" >/dev/null \
    || record_failure "zero-ready truth state mismatch for ${case_id}"
  "$replay" --bundle-dir "$output_dir" >/dev/null \
    || record_failure "replay failed for ${case_id}"
  if [[ "$case_id" == "safe" ]]; then
    grep -Fq 'Advisory only' "${output_dir}/operator_status.md" || record_failure "safe status missing pasteable advisory"
  fi
  if [[ "$zero_truth_case" == "source-gap" ]]; then
    jq -e '.zero_ready_truth.reason_codes | index("FE-IWXII-SOURCE-GAP-PROPOSAL") and index("FE-IWXII-SEMANTIC-CONTRADICTION")' "${output_dir}/operator_truth_gate_report.json" >/dev/null \
      || record_failure "source-gap reason codes missing"
    grep -Fq 'Review ' "${output_dir}/operator_status.md" || record_failure "source-gap status missing review command"
  fi
  if [[ "$zero_truth_case" == "missing" && "$case_id" == "safe" ]]; then
    jq -e '.zero_ready_truth.reason_codes | index("FE-IWXII-MISSING-CLOSED-BEAD-PROOF") and index("FE-IWXII-MISSING-SOURCE-GAP-PICKER")' "${output_dir}/operator_truth_gate_report.json" >/dev/null \
      || record_failure "missing scan reason codes missing"
    grep -Fq 'idea_wizard_xii_zero_ready_source_gap_picker.sh' "${output_dir}/operator_status.md" \
      || record_failure "missing scan status lacks source-gap command"
  fi
  record_pass "${case_id}-${zero_truth_case}"
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
  run_case safe green 0 clean true_saturation
  run_case safe degraded 0 source-gap source_gap_found
  run_case safe degraded 0 missing degraded_unknown
  run_case forbidden fail_closed 42 clean true_saturation
  run_case missing-required fail_closed 42 clean true_saturation
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
