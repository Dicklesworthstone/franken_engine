#!/usr/bin/env bash
# CEI G.1 (bd-sde5e.7.1): claim-evidence integrity capstone replay wrapper.
#
# Re-runs scripts/run_claim_evidence_integrity_capstone.sh against a pinned (or
# auto-detected latest) previous bundle and confirms the overall verdict and the
# per-sub-gate verdicts reproduce. Fails CLOSED on an incomplete bundle: a source
# or replay bundle missing any required artifact is a hard error, never a silent
# pass.
#
# Usage:
#   scripts/e2e/claim_evidence_integrity_capstone_replay.sh [ci|selftest]
#   CLAIM_EVIDENCE_INTEGRITY_CAPSTONE_REPLAY_RUN_DIR=<bundle> \
#     scripts/e2e/claim_evidence_integrity_capstone_replay.sh ci
#
# Environment:
#   CLAIM_EVIDENCE_INTEGRITY_CAPSTONE_REPLAY_RUN_DIR  pin the SOURCE bundle to
#     replay against (else the latest under the artifact root is used).
#   CLAIM_EVIDENCE_INTEGRITY_CAPSTONE_ARTIFACT_ROOT   override the base dir.
#   FRANKEN_EVIDENCE_MANIFEST_BIN                      prebuilt audit binary,
#     forwarded to the capstone's sub-gates to skip a cargo build.
#
# Exit codes:
#   0 — replay verdict + per-sub-gate verdicts match the source
#   1 — no previous bundle found
#   2 — bundle validation failed (incomplete bundle; fail-closed)
#   3 — overall verdict mismatch between source and replay
#   4 — a per-sub-gate verdict mismatch between source and replay
set -euo pipefail

export TZ=UTC LC_ALL=C LANG=C

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
project_dir="$(cd "${script_dir}/../.." && pwd)"
cd "${project_dir}"

mode="${1:-selftest}"
[[ "$mode" == "selftest" ]] && mode="ci"

if ! command -v jq >/dev/null 2>&1; then
  echo "ERROR: jq is required" >&2
  exit 2
fi

gate_script="${project_dir}/scripts/run_claim_evidence_integrity_capstone.sh"
artifact_root="${CLAIM_EVIDENCE_INTEGRITY_CAPSTONE_ARTIFACT_ROOT:-artifacts/claim_evidence_integrity_capstone}"
replay_ts="$(date -u +%Y%m%dT%H%M%SZ)"
replay_dir="${artifact_root}_replay/${replay_ts}"
mkdir -p "${replay_dir}"

required_artifacts=(
  "run_manifest.json"
  "events.jsonl"
  "commands.txt"
  "summary.txt"
  "step_logs"
)

validate_bundle() {
  local dir="$1" label="$2" missing=0 art
  for art in "${required_artifacts[@]}"; do
    if [[ ! -e "${dir}/${art}" ]]; then
      echo "ERROR: ${label} bundle missing required artifact: ${art}" >&2
      missing=1
    fi
  done
  if [[ -f "${dir}/run_manifest.json" ]]; then
    if ! jq -e '.schema_version == "franken-engine.claim-evidence-integrity-capstone.run-manifest.v1"' \
          "${dir}/run_manifest.json" >/dev/null 2>&1; then
      echo "ERROR: ${label} bundle run_manifest schema mismatch" >&2
      missing=1
    fi
  fi
  if [[ -f "${dir}/events.jsonl" ]]; then
    if [[ ! -s "${dir}/events.jsonl" ]] || ! jq -e . "${dir}/events.jsonl" >/dev/null 2>&1; then
      echo "ERROR: ${label} bundle events.jsonl empty or invalid JSONL" >&2
      missing=1
    fi
  fi
  return "${missing}"
}

# Locate + validate the source bundle
pin="${CLAIM_EVIDENCE_INTEGRITY_CAPSTONE_REPLAY_RUN_DIR:-}"
if [[ -n "${pin}" ]]; then
  source_bundle="${pin}"
  [[ -d "${source_bundle}" ]] || { echo "ERROR: pinned replay run dir not found: ${source_bundle}" >&2; exit 1; }
else
  [[ -d "${artifact_root}" ]] || { echo "ERROR: no prior runs at ${artifact_root} — run the capstone first" >&2; exit 1; }
  source_bundle="$(find "${artifact_root}" -maxdepth 1 -mindepth 1 -type d -name '*T*Z' | sort | tail -1)"
  [[ -n "${source_bundle}" && -d "${source_bundle}" ]] || { echo "ERROR: could not auto-detect a prior bundle under ${artifact_root}" >&2; exit 1; }
fi
echo "replay source bundle: ${source_bundle}"

validate_bundle "${source_bundle}" "source" || { echo "ERROR: source bundle incomplete; refusing to replay (fail-closed)" >&2; exit 2; }

source_manifest="${source_bundle}/run_manifest.json"
source_verdict="$(jq -r '.verdict' "${source_manifest}")"
source_subgates="$(jq -rS '[.subgates[] | {label, verdict}] | sort_by(.label)' "${source_manifest}")"
echo "source: verdict=${source_verdict}"

# Re-run the capstone into the replay dir
replay_run_dir="${replay_dir}/replay_run"
mkdir -p "${replay_run_dir}"
if ! CLAIM_EVIDENCE_INTEGRITY_CAPSTONE_REPLAY_RUN_DIR="${replay_run_dir}" \
     "${gate_script}" "${mode}" "${replay_run_dir}" \
     >"${replay_dir}/replay_stdout.log" 2>"${replay_dir}/replay_stderr.log"; then
  echo "NOTE: replay capstone exited non-zero (expected when the tree is red) — comparison still proceeds" >&2
fi

validate_bundle "${replay_run_dir}" "replay" || { echo "ERROR: replay bundle incomplete (fail-closed)" >&2; exit 2; }

replay_manifest="${replay_run_dir}/run_manifest.json"
replay_verdict="$(jq -r '.verdict' "${replay_manifest}")"
replay_subgates="$(jq -rS '[.subgates[] | {label, verdict}] | sort_by(.label)' "${replay_manifest}")"
echo "replay: verdict=${replay_verdict}"

# Compare
exit_code=0
verdict_match=true
subgate_match=true
if [[ "${source_verdict}" != "${replay_verdict}" ]]; then
  echo "DIFF: overall verdict mismatch (source=${source_verdict} replay=${replay_verdict})" >&2
  verdict_match=false
  exit_code=3
fi
if [[ "${source_subgates}" != "${replay_subgates}" ]]; then
  echo "DIFF: per-sub-gate verdicts mismatch" >&2
  subgate_match=false
  [[ "${exit_code}" -eq 0 ]] && exit_code=4
fi

comparison_report="${replay_dir}/comparison_report.json"
jq -n \
  --arg schema_version "franken-engine.claim-evidence-integrity-capstone.replay-report.v1" \
  --arg replay_ts "${replay_ts}" \
  --arg mode "${mode}" \
  --arg source_bundle "${source_bundle}" \
  --arg replay_bundle "${replay_run_dir}" \
  --arg source_verdict "${source_verdict}" \
  --arg replay_verdict "${replay_verdict}" \
  --argjson verdict_match "${verdict_match}" \
  --argjson subgate_match "${subgate_match}" \
  --argjson exit_code "${exit_code}" \
  '{
    schema_version: $schema_version,
    replay_ts: $replay_ts,
    mode: $mode,
    source_bundle: $source_bundle,
    replay_bundle: $replay_bundle,
    source_verdict: $source_verdict,
    replay_verdict: $replay_verdict,
    verdict_match: $verdict_match,
    subgate_match: $subgate_match,
    exit_code: $exit_code
  }' >"${comparison_report}"

echo "capstone_replay_report=${comparison_report}"
if [[ "${exit_code}" -eq 0 ]]; then
  echo "REPLAY OK: capstone verdict + per-sub-gate verdicts reproduced (verdict=${source_verdict})"
else
  echo "REPLAY MISMATCH: exit_code=${exit_code}" >&2
fi
exit "${exit_code}"
