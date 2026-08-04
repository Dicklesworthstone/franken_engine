#!/usr/bin/env bash
# CEI H.1 (bd-sde5e.8.1) gate — Merkle-committed Claim-Evidence Ledger.
#
# Recomputes the Claim-Evidence Ledger from the live claim-to-proof matrix and the
# committed per-claim evidence manifests (docs/evidence/<CLAIM>/), then verifies it
# against the committed MMR root at docs/claim_evidence_ledger_root.txt:
#
#   * the recomputed RFC-6962 (mmr_proof.rs) root equals the committed root;
#   * the leaf count and the flat leaves digest match;
#   * every committed per-leaf record reproduces exactly;
#   * every leaf carries a valid inclusion proof against the recomputed root.
#
# Any silent matrix/README/evidence edit that is not accompanied by a regenerated,
# evidence-consistent root changes a leaf, hence the root, and FAILS this gate
# closed. To regenerate after an intentional, evidence-consistent change:
#
#   cargo run -q -p frankenengine-engine --bin franken_claim_evidence_ledger -- generate
#
# Verification recomputes against the PINNED as_of_unix in the committed file, not
# the wall clock, so the gate is stable under the passage of time and fails only on
# a real content edit. Live freshness decay is the A.3 audit's job
# (run_claim_evidence_integrity.sh), not this gate's.
#
# Modes:
#   ci | check   build the verifier if needed, verify, fail closed on divergence.
#
# Standard bundle: every run writes a content-addressed bundle under
# artifacts/claim_evidence_ledger/<ts>/ (or an explicit run dir):
#   run_manifest.json   schema'd verdict + roots + per-file sha256 + git rev
#   verify_report.txt    the raw verifier stdout (roots + per-check booleans)
#   events.jsonl         structured trace events (one JSON object per line)
#   trace_ids.json       the trace/decision/policy ids for cross-referencing
#   commands.txt         every command run, in order
#   step_logs/           per-step stdout/stderr logs (step_000.log ...)
#
# Run-dir override (replay): pass an explicit run dir as $2 or set
# CLAIM_EVIDENCE_LEDGER_REPLAY_RUN_DIR so the replay wrapper can pin the output.
#
# Honors FRANKEN_CLAIM_EVIDENCE_LEDGER_BIN to skip the build (a prebuilt binary).
set -euo pipefail

root_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$root_dir"

mode="${1:-ci}"
case "$mode" in
  ci | check) ;;
  *)
    echo "usage: run_claim_evidence_ledger_gate.sh [ci|check] [run_dir]" >&2
    exit 2
    ;;
esac

if ! command -v jq >/dev/null 2>&1; then
  echo "jq is required for the claim-evidence ledger standard bundle" >&2
  exit 2
fi

artifact_root="${CLAIM_EVIDENCE_LEDGER_ARTIFACT_ROOT:-artifacts/claim_evidence_ledger}"
timestamp="$(date -u +%Y%m%dT%H%M%SZ)"
default_run_dir="${CLAIM_EVIDENCE_LEDGER_REPLAY_RUN_DIR:-${artifact_root}/${timestamp}}"
run_dir="${2:-$default_run_dir}"
report_path="${run_dir}/verify_report.txt"
manifest_path="${run_dir}/run_manifest.json"
commands_path="${run_dir}/commands.txt"
events_path="${run_dir}/events.jsonl"
trace_ids_path="${run_dir}/trace_ids.json"
step_logs_dir="${run_dir}/step_logs"
mkdir -p "$run_dir" "$step_logs_dir"
: >"$commands_path"
: >"$events_path"

trace_id="trace-claim-evidence-ledger-${timestamp}"
decision_id="decision-claim-evidence-ledger-${timestamp}"
policy_id="policy-claim-evidence-ledger-v1"
component="claim_evidence_ledger_gate"
schema_ns="franken-engine.claim-evidence-ledger-gate"

append_event() {
  # append_event <event> <outcome> <detail>
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

append_event "gate.start" "info" "mode=${mode}"

# ---------------------------------------------------------------------------
# Step 0 — locate or build the verifier binary
# ---------------------------------------------------------------------------
preflight_log="${step_logs_dir}/step_000.log"
{
  printf '==> step 0: locate franken_claim_evidence_ledger binary\n'
  bin="${FRANKEN_CLAIM_EVIDENCE_LEDGER_BIN:-}"
  if [[ -z "$bin" ]]; then
    for cand in \
      "target/debug/franken_claim_evidence_ledger" \
      "target/release/franken_claim_evidence_ledger"; do
      if [[ -x "$cand" ]]; then bin="$cand"; break; fi
    done
  fi
} >"$preflight_log" 2>&1

if [[ -z "${bin:-}" ]]; then
  echo "building franken_claim_evidence_ledger ..." >&2
  printf 'cargo build -p frankenengine-engine --bin franken_claim_evidence_ledger\n' >>"$commands_path"
  cargo build -p frankenengine-engine --bin franken_claim_evidence_ledger >>"$preflight_log" 2>&1
  bin="target/debug/franken_claim_evidence_ledger"
fi
printf 'located verifier binary: %s\n' "$bin" >>"$preflight_log"
append_event "gate.preflight" "ok" "bin=${bin}"

# ---------------------------------------------------------------------------
# Step 1 — verify the live matrix/evidence against the committed root
# ---------------------------------------------------------------------------
verify_log="${step_logs_dir}/step_001.log"
printf '%s verify\n' "$bin" >>"$commands_path"

set +e
"$bin" verify >"$report_path" 2>"$verify_log"
verify_exit="$?"
set -e
cat "$report_path"

verdict=$([[ "$verify_exit" -eq 0 ]] && echo "pass" || echo "fail")
committed_root="$(grep -m1 'committed root' "$report_path" | awk '{print $4}' || true)"
recomputed_root="$(grep -m1 'recomputed root' "$report_path" | awk '{print $3}' || true)"
append_event "gate.verify" "$verdict" "exit=${verify_exit}"

# ---------------------------------------------------------------------------
# Step 2 — emit trace ids + content-addressed run manifest
# ---------------------------------------------------------------------------
report_sha="$(sha256sum "$report_path" | cut -d' ' -f1)"
events_sha="$(sha256sum "$events_path" | cut -d' ' -f1)"
commands_sha="$(sha256sum "$commands_path" | cut -d' ' -f1)"
root_file_sha="$(sha256sum docs/claim_evidence_ledger_root.txt 2>/dev/null | cut -d' ' -f1 || echo missing)"
git_rev="$(git rev-parse HEAD 2>/dev/null || echo unknown)"

jq -nc \
  --arg schema_version "${schema_ns}.trace-ids.v1" \
  --arg trace_id "${trace_id}" \
  --arg decision_id "${decision_id}" \
  --arg policy_id "${policy_id}" \
  --arg component "${component}" \
  '{
    schema_version: $schema_version,
    trace_id: $trace_id,
    decision_id: $decision_id,
    policy_id: $policy_id,
    component: $component
  }' >"$trace_ids_path"

jq -n \
  --arg schema_version "${schema_ns}.run-manifest.v1" \
  --arg mode "${mode}" \
  --argjson verify_exit_code "${verify_exit}" \
  --arg verdict "${verdict}" \
  --arg committed_root "${committed_root}" \
  --arg recomputed_root "${recomputed_root}" \
  --arg trace_id "${trace_id}" \
  --arg git_rev "${git_rev}" \
  --arg verify_report_sha256 "${report_sha}" \
  --arg events_sha256 "${events_sha}" \
  --arg commands_sha256 "${commands_sha}" \
  --arg root_file_sha256 "${root_file_sha}" \
  --arg owning_bead "bd-sde5e.8.1" \
  '{
    schema_version: $schema_version,
    mode: $mode,
    verify_exit_code: $verify_exit_code,
    verdict: $verdict,
    committed_root: $committed_root,
    recomputed_root: $recomputed_root,
    trace_id: $trace_id,
    git_rev: $git_rev,
    artifacts: {
      verify_report: "verify_report.txt",
      events: "events.jsonl",
      trace_ids: "trace_ids.json",
      commands: "commands.txt",
      step_logs: "step_logs"
    },
    content_hashes: {
      "verify_report.txt": $verify_report_sha256,
      "events.jsonl": $events_sha256,
      "commands.txt": $commands_sha256,
      "docs/claim_evidence_ledger_root.txt": $root_file_sha256
    },
    owning_bead: $owning_bead
  }' >"$manifest_path"

append_event "gate.manifest" "ok" "root_file_sha256=${root_file_sha}"
append_event "gate.end" "$verdict" "run_dir=${run_dir}"

echo "claim_evidence_ledger_report=${report_path}"
echo "claim_evidence_ledger_manifest=${manifest_path}"
echo "claim_evidence_ledger_events=${events_path}"
echo "claim_evidence_ledger_run_dir=${run_dir}"
echo "claim_evidence_ledger_verdict=${verdict}"

# Tamper-evidence gate: a root mismatch is always a hard failure (there is no
# advisory reason to tolerate committed content drifting from the committed root).
exit "$verify_exit"
