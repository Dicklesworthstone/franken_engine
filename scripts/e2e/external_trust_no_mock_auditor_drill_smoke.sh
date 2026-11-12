#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "${repo_root}" || exit 1

frankenctl_bin="${FRANKENCTL_BIN:-target/release/frankenctl}"
if [[ ! -x "${frankenctl_bin}" ]]; then
  printf 'frankenctl binary not executable at %s\n' "${frankenctl_bin}" >&2
  exit 2
fi

workdir="$(mktemp -d "${TMPDIR:-/tmp}/external-trust-auditor-drill-smoke.XXXXXX")"

# 1. Fixture/replay mode must pass deterministically (overall_decision == pass)
fixture_out="${workdir}/fixture_run"
python3 scripts/external_trust_no_mock_auditor_drill.py \
  --mode fixture \
  --frankenctl-bin "${frankenctl_bin}" \
  --out-dir "${fixture_out}" >"${workdir}/fixture_stdout.json"

jq -e '.overall_decision == "pass" and .stage_count == 12' "${fixture_out}/run_manifest.json" >/dev/null
python3 scripts/check_external_trust_auditor_drill_truth_gate.py \
  --drill-dir "${fixture_out}" >"${workdir}/fixture_gate.json"
jq -e '.verdict == "pass" and (.violations | length == 0)' "${workdir}/fixture_gate.json" >/dev/null

# 2. Live-artifact mode must run truthfully without mutating repo files
live_out="${workdir}/live_run"
python3 scripts/external_trust_no_mock_auditor_drill.py \
  --mode live \
  --frankenctl-bin "${frankenctl_bin}" \
  --out-dir "${live_out}" >"${workdir}/live_stdout.json"

jq -e '(.overall_decision == "pass" or .overall_decision == "degraded") and .immutability_guard.mutated == false' \
  "${live_out}/run_manifest.json" >/dev/null
python3 scripts/check_external_trust_auditor_drill_truth_gate.py \
  --drill-dir "${live_out}" >"${workdir}/live_gate.json"
jq -e '.verdict == "pass" and (.violations | length == 0)' "${workdir}/live_gate.json" >/dev/null

# 3. Truth gate negative test A: missing required stage in green manifest -> fail_closed
tamper_missing="${workdir}/tamper_missing_stage"
cp -R "${fixture_out}" "${tamper_missing}"
jq '.stages |= map(select(.stage_id != "09_e8_report_healthy_with_capstone"))' \
  "${fixture_out}/run_manifest.json" >"${tamper_missing}/run_manifest.json"
if python3 scripts/check_external_trust_auditor_drill_truth_gate.py --drill-dir "${tamper_missing}" >"${workdir}/tamper_missing_gate.json"; then
  printf 'FAIL: truth gate accepted missing required stage\n' >&2
  exit 1
fi
jq -e '.verdict == "fail_closed" and ((.violations | index("missing_required_stage:09_e8_report_healthy_with_capstone")) != null)' \
  "${workdir}/tamper_missing_gate.json" >/dev/null

# 4. Truth gate negative test B: contradictory stage receipt (receipt says fail_closed while manifest says pass)
tamper_contradict="${workdir}/tamper_contradictory_receipt"
cp -R "${fixture_out}" "${tamper_contradict}"
jq '.decision = "fail_closed" | .reason_codes = ["stale_artifact"]' \
  "${fixture_out}/stages/04_bundle_doctor_healthy.json" >"${tamper_contradict}/stages/04_bundle_doctor_healthy.json"
new_sha="$(sha256sum "${tamper_contradict}/stages/04_bundle_doctor_healthy.json" | awk '{print $1}')"
jq --arg sha "${new_sha}" '
  .stages |= map(
    if .stage_id == "04_bundle_doctor_healthy" then
      .receipt_sha256 = $sha | .actual_decision = "fail_closed"
    else . end
  )
' "${fixture_out}/run_manifest.json" >"${tamper_contradict}/run_manifest.json"
if python3 scripts/check_external_trust_auditor_drill_truth_gate.py --drill-dir "${tamper_contradict}" >"${workdir}/tamper_contradict_gate.json"; then
  printf 'FAIL: truth gate accepted contradictory green claim\n' >&2
  exit 1
fi
jq -e '.verdict == "fail_closed" and ((.violations | index("contradictory_green_overall_decision")) != null)' \
  "${workdir}/tamper_contradict_gate.json" >/dev/null

# 5. Truth gate negative test C: negative guard forged to supported -> fail_closed
tamper_mock="${workdir}/tamper_mock_bypass"
cp -R "${fixture_out}" "${tamper_mock}"
jq '.decision = "supported" | .reason_codes = []' \
  "${fixture_out}/stages/06_bundle_doctor_mock_contaminated_fail_closed.json" >"${tamper_mock}/stages/06_bundle_doctor_mock_contaminated_fail_closed.json"
mock_sha="$(sha256sum "${tamper_mock}/stages/06_bundle_doctor_mock_contaminated_fail_closed.json" | awk '{print $1}')"
jq --arg sha "${mock_sha}" '
  .stages |= map(
    if .stage_id == "06_bundle_doctor_mock_contaminated_fail_closed" then
      .receipt_sha256 = $sha | .actual_decision = "supported"
    else . end
  )
' "${fixture_out}/run_manifest.json" >"${tamper_mock}/run_manifest.json"
if python3 scripts/check_external_trust_auditor_drill_truth_gate.py --drill-dir "${tamper_mock}" >"${workdir}/tamper_mock_gate.json"; then
  printf 'FAIL: truth gate accepted forged mock-contaminated supported receipt\n' >&2
  exit 1
fi
jq -e '.verdict == "fail_closed" and ((.violations | index("negative_guard_falsely_supported:06_bundle_doctor_mock_contaminated_fail_closed")) != null)' \
  "${workdir}/tamper_mock_gate.json" >/dev/null

printf 'PASS external trust no-mock auditor drill & paired truth gate smoke (workdir=%s)\n' "${workdir}"
