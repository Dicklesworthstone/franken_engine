#!/usr/bin/env bash
# CEI G.1 (bd-sde5e.7.1) — Claim-Evidence Integrity Capstone meta-gate.
#
# One button an operator/CI runs to assert the project is not over-promising. It
# composes the four CEI integrity checks and fails closed on ANY over-promotion,
# internal contradiction, uncommitted artifact, pending receipt, stale-past-the-
# e-process evidence, ledger/matrix drift, or Test262 posture drift:
#
#   A  bidirectional + wording + artifact-quality + whole-document consistency
#        scripts/run_claim_to_proof_matrix_gate.sh ci
#          (README/doc wording <= matrix.allowed_state; artifact-quality refusal of
#           simulated/mock evidence; CEI A.2 whole-document claim consistency)
#        scripts/run_claim_evidence_integrity.sh blocking
#          (CEI A.1/A.3 bidirectional lattice: matrix.asserted_state <=
#           ceiling(evidence_tier) for every row, from machine-checkable facts only)
#   B  committed evidence, tamper-evident
#        scripts/run_claim_evidence_ledger_gate.sh ci
#          (CEI H.1 Merkle/MMR: committed docs/claim_evidence_ledger_root.txt equals
#           the root recomputed from the live matrix + committed per-claim manifests)
#   C  reconciliation consistency
#        enforced inside the matrix gate (A.2 whole-document consistency index) — a
#        re-introduced README/matrix contradiction turns step A red.
#   D  Test262 honesty posture
#        scripts/run_test262_posture_consistency.sh ci
#          (CEI D.1/D.3: full_suite_claim_allowed=false + matrix row + README agree)
#
# ACCEPTANCE (bd-sde5e.7.1): green only when ALL of A-D hold; injecting one
# over-promotion (untrack an artifact, flip a receipt to pending, re-introduce a
# README contradiction, edit a committed leaf without regenerating the ledger root,
# or drift the Test262 posture) turns exactly that sub-gate — and the capstone — red.
#
# Standard bundle (emitted every run under
# artifacts/claim_evidence_integrity_capstone/<ts>/ or an explicit run dir):
#   run_manifest.json   schema'd verdict + per-sub-gate verdicts + per-file sha256
#   events.jsonl        structured trace events (one JSON object per line)
#   commands.txt        every sub-gate command run, in order
#   step_logs/          per-sub-gate stdout/stderr (step_000_*.log ...)
#   summary.txt         operator-readable roll-up
#
# Run-dir override (replay): pass an explicit run dir as $2 or set
# CLAIM_EVIDENCE_INTEGRITY_CAPSTONE_REPLAY_RUN_DIR so the e2e replay wrapper can pin
# the output location and diff the verdict.
#
# To reuse a prebuilt audit binary across the sub-gates (skip rebuilds), export
# FRANKEN_EVIDENCE_MANIFEST_BIN=<path-to-franken_evidence_manifest>.
set -euo pipefail

root_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$root_dir"

mode="${1:-ci}"
if [[ "$mode" != "ci" && "$mode" != "dev" ]]; then
  echo "Usage: $0 {ci|dev} [run_dir]" >&2
  echo "  ci   fail closed on any sub-gate failure (the capstone contract)" >&2
  echo "  dev  advisory: run every sub-gate, report, but always exit 0" >&2
  exit 2
fi

if ! command -v jq >/dev/null 2>&1; then
  echo "jq is required for the claim-evidence integrity capstone" >&2
  exit 2
fi

artifact_root="${CLAIM_EVIDENCE_INTEGRITY_CAPSTONE_ARTIFACT_ROOT:-artifacts/claim_evidence_integrity_capstone}"
timestamp="$(date -u +%Y%m%dT%H%M%SZ)"
default_run_dir="${CLAIM_EVIDENCE_INTEGRITY_CAPSTONE_REPLAY_RUN_DIR:-${artifact_root}/${timestamp}}"
run_dir="${2:-$default_run_dir}"
manifest_path="${run_dir}/run_manifest.json"
commands_path="${run_dir}/commands.txt"
events_path="${run_dir}/events.jsonl"
summary_path="${run_dir}/summary.txt"
step_logs_dir="${run_dir}/step_logs"
mkdir -p "$run_dir" "$step_logs_dir"
: >"$commands_path"
: >"$events_path"

trace_id="trace-cei-capstone-${timestamp}"
decision_id="decision-cei-capstone-${timestamp}"
policy_id="policy-cei-capstone-v1"
component="claim_evidence_integrity_capstone"
schema_ns="franken-engine.claim-evidence-integrity-capstone"

append_event() {
  jq -nc \
    --arg schema_version "${schema_ns}.event.v1" \
    --arg trace_id "${trace_id}" \
    --arg decision_id "${decision_id}" \
    --arg policy_id "${policy_id}" \
    --arg component "${component}" \
    --arg event "$1" \
    --arg outcome "$2" \
    --arg detail "$3" \
    '{
      schema_version: $schema_version,
      trace_id: $trace_id,
      decision_id: $decision_id,
      policy_id: $policy_id,
      component: $component,
      event: $event,
      outcome: $outcome,
      detail: (if $detail == "" then null else $detail end)
    }' >>"${events_path}"
}

append_event "capstone.start" "info" "mode=${mode}"

# Each sub-gate result is recorded as one JSON object appended to this file, then
# slurped into the run manifest at the end.
results_path="${run_dir}/.subgate_results.jsonl"
: >"$results_path"

overall_exit=0
declare -i step_index=0

# run_subgate <track> <label> <expected> -- <command...>
#   track    : the CEI track letter(s) this sub-gate covers (for the manifest)
#   label    : short stable id used in the step log name and manifest
#   expected : human note on what a red verdict means
run_subgate() {
  local track="$1" label="$2" expected="$3"
  shift 3
  [[ "$1" == "--" ]] && shift
  local step
  step="$(printf '%03d' "$step_index")"
  local log="${step_logs_dir}/step_${step}_${label}.log"

  {
    printf '# sub-gate %s (track %s): %s\n' "$label" "$track" "$expected"
    printf '%q ' "$@"
    printf '\n'
  } >>"$commands_path"

  append_event "subgate.start" "info" "label=${label} track=${track}"

  local exit_code=0
  set +e
  "$@" >"$log" 2>&1
  exit_code=$?
  set -e

  local verdict="pass"
  if [[ "$exit_code" -ne 0 ]]; then
    verdict="fail"
    overall_exit=1
  fi

  local log_sha
  log_sha="$(sha256sum "$log" | cut -d' ' -f1)"

  jq -nc \
    --arg label "$label" \
    --arg track "$track" \
    --argjson exit_code "$exit_code" \
    --arg verdict "$verdict" \
    --arg expected "$expected" \
    --arg log "step_logs/step_${step}_${label}.log" \
    --arg log_sha256 "$log_sha" \
    '{label:$label, track:$track, exit_code:$exit_code, verdict:$verdict,
      expected_red_meaning:$expected, log:$log, log_sha256:$log_sha256}' >>"$results_path"

  append_event "subgate.end" "$verdict" "label=${label} exit=${exit_code}"
  printf '[%s] track %s -> %s (exit=%s)\n' "$label" "$track" "$verdict" "$exit_code"
  step_index+=1
}

# Sub-gate A.1: README/doc wording <= matrix.allowed_state + artifact quality + A.2
run_subgate "A,C" "claim_to_proof_matrix" \
  "README/doc wording exceeds matrix.allowed_state, artifact cites mock/simulated evidence, or a whole-document claim contradiction was re-introduced" \
  -- ./scripts/run_claim_to_proof_matrix_gate.sh ci

# Sub-gate A.2/B: matrix.asserted_state <= ceiling(evidence_tier) for every row
run_subgate "A,B" "bidirectional_lattice" \
  "a row asserts more than its committed evidence licenses (untracked artifact, pending/backfill receipt, missing repro.lock, or stale-past-e-process)" \
  -- ./scripts/run_claim_evidence_integrity.sh blocking

# Sub-gate B/H.1: committed Merkle ledger root equals recomputed root
run_subgate "B" "merkle_ledger" \
  "the committed claim_evidence_ledger_root.txt diverges from the root recomputed over the live matrix + committed manifests (a silent leaf edit)" \
  -- ./scripts/run_claim_evidence_ledger_gate.sh ci

# Sub-gate D: Test262 honesty posture cross-file consistency
run_subgate "D" "test262_posture" \
  "the Test262 posture drifted (full_suite_claim_allowed, matrix FE-CLAIM-TEST262 row, and README wording disagree)" \
  -- ./scripts/run_test262_posture_consistency.sh ci

# ---------------------------------------------------------------------------
# Roll-up manifest + summary
# ---------------------------------------------------------------------------
verdict="pass"
[[ "$overall_exit" -ne 0 ]] && verdict="fail"
# dev mode is advisory: report the real verdict but never fail the build.
effective_exit="$overall_exit"
[[ "$mode" == "dev" ]] && effective_exit=0

git_rev="$(git rev-parse HEAD 2>/dev/null || echo unknown)"
commands_sha="$(sha256sum "$commands_path" | cut -d' ' -f1)"
events_sha="$(sha256sum "$events_path" | cut -d' ' -f1)"
failed_labels="$(jq -r 'select(.verdict=="fail") | .label' "$results_path" | paste -sd, - 2>/dev/null || true)"

jq -n \
  --arg schema_version "${schema_ns}.run-manifest.v1" \
  --arg mode "${mode}" \
  --arg verdict "${verdict}" \
  --argjson overall_exit_code "${overall_exit}" \
  --arg failed_subgates "${failed_labels}" \
  --arg trace_id "${trace_id}" \
  --arg decision_id "${decision_id}" \
  --arg policy_id "${policy_id}" \
  --arg git_rev "${git_rev}" \
  --arg commands_sha256 "${commands_sha}" \
  --arg events_sha256 "${events_sha}" \
  --slurpfile subgates "$results_path" \
  --arg owning_bead "bd-sde5e.7.1" \
  '{
    schema_version: $schema_version,
    mode: $mode,
    verdict: $verdict,
    overall_exit_code: $overall_exit_code,
    failed_subgates: (if $failed_subgates == "" then null else $failed_subgates end),
    composed_tracks: ["A","B","C","D"],
    subgates: $subgates,
    trace_id: $trace_id,
    decision_id: $decision_id,
    policy_id: $policy_id,
    git_rev: $git_rev,
    artifacts: {events: "events.jsonl", commands: "commands.txt", summary: "summary.txt", step_logs: "step_logs"},
    content_hashes: {"commands.txt": $commands_sha256, "events.jsonl": $events_sha256},
    owning_bead: $owning_bead
  }' >"$manifest_path"

rm -f "$results_path"

{
  echo "Claim-Evidence Integrity Capstone (CEI G.1, bd-sde5e.7.1)"
  echo "========================================================="
  echo "mode:    ${mode}"
  echo "verdict: ${verdict}"
  echo "git_rev: ${git_rev}"
  echo ""
  echo "Composed sub-gates (red on any over-promotion):"
  jq -r '.subgates[] | "  [\(.verdict|ascii_upcase)] \(.label) (track \(.track), exit \(.exit_code))"' "$manifest_path"
  if [[ "$verdict" == "fail" ]]; then
    echo ""
    echo "FAILED: ${failed_labels}"
    echo "See step_logs/ for the failing sub-gate's output."
  fi
} >"$summary_path"
cat "$summary_path"

append_event "capstone.end" "$verdict" "run_dir=${run_dir} mode=${mode}"

echo "claim_evidence_integrity_capstone_manifest=${manifest_path}"
echo "claim_evidence_integrity_capstone_verdict=${verdict}"
echo "claim_evidence_integrity_capstone_run_dir=${run_dir}"

exit "$effective_exit"
