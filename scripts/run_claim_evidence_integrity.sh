#!/usr/bin/env bash
# CEI A.3 (bd-sde5e.1.3) gate + A.6 (bd-sde5e.1.6) standard-bundle runner.
#
# Scores the live claim-to-proof matrix against the *committed* evidence
# (docs/evidence/<CLAIM>/) using the bidirectional soundness lattice
# (crates/franken-engine/src/claim_evidence_lattice.rs, CEI A.1): for every row it
# checks that the asserted state does not exceed ceiling(evidence_tier), where the
# tier is derived only from machine-checkable facts -- artifact git-tracked,
# manifest verification_result == passed AND not backfill, a committed repro.lock,
# a zero-exit receipt, and freshness judged by the A.4 anytime-valid e-process
# boundary (crates/franken-engine/src/claim_evidence_lattice.rs::FreshnessEProcess).
#
# This is the enforcement half the historical claim-to-proof gate lacked (which
# only checked README-wording <= matrix.allowed_state, never matrix <= evidence).
#
# Modes:
#   ci          advisory (default): reports over-promoted rows, exits 0.
#   blocking    fail-closed: exits 1 if any row asserts more than its evidence
#               licenses. The G.1 meta-gate composes this once Track B has
#               re-emitted real receipts for every OBSERVED row.
#
# Standard bundle (CEI A.6): every run writes a content-addressed bundle under
# artifacts/claim_evidence_integrity/<ts>/ (or an explicit run dir, see below):
#   run_manifest.json   schema'd verdict + coverage + per-file sha256 + host facts
#   audit_report.txt    the raw audit stdout (over-promotion list + coverage)
#   events.jsonl        structured trace events (one JSON object per line)
#   trace_ids.json      the trace/decision/policy ids for cross-referencing
#   commands.txt        every command run, in order
#   step_logs/          per-step stdout/stderr logs (step_000.log ...)
#
# Run-dir override (CEI A.6 replay): pass an explicit run dir as $2 or set
# CLAIM_EVIDENCE_INTEGRITY_REPLAY_RUN_DIR so a replay wrapper can pin the output
# location and diff the verdict byte-for-byte.
#
# Honors FRANKEN_EVIDENCE_MANIFEST_BIN to skip the build (a prebuilt binary).
set -euo pipefail

root_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$root_dir"

mode="${1:-ci}"
blocking_flag=""
blocking_bool="false"
if [[ "$mode" == "blocking" || "${CLAIM_EVIDENCE_INTEGRITY_BLOCKING:-0}" == "1" ]]; then
  blocking_flag="--blocking"
  blocking_bool="true"
fi

if ! command -v jq >/dev/null 2>&1; then
  echo "jq is required for the claim-evidence integrity standard bundle" >&2
  exit 2
fi

artifact_root="${CLAIM_EVIDENCE_INTEGRITY_ARTIFACT_ROOT:-artifacts/claim_evidence_integrity}"
timestamp="$(date -u +%Y%m%dT%H%M%SZ)"

# Run-dir override (A.6 replay): explicit $2 wins, then the env pin, else a
# fresh timestamped dir under the artifact root.
default_run_dir="${CLAIM_EVIDENCE_INTEGRITY_REPLAY_RUN_DIR:-${artifact_root}/${timestamp}}"
run_dir="${2:-$default_run_dir}"
report_path="${run_dir}/audit_report.txt"
manifest_path="${run_dir}/run_manifest.json"
commands_path="${run_dir}/commands.txt"
events_path="${run_dir}/events.jsonl"
trace_ids_path="${run_dir}/trace_ids.json"
step_logs_dir="${run_dir}/step_logs"
mkdir -p "$run_dir" "$step_logs_dir"
: >"$commands_path"
: >"$events_path"

trace_id="trace-claim-evidence-integrity-${timestamp}"
decision_id="decision-claim-evidence-integrity-${timestamp}"
policy_id="policy-claim-evidence-integrity-v1"
component="claim_evidence_integrity_gate"
schema_ns="franken-engine.claim-evidence-integrity-gate"

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

append_event "gate.start" "info" "mode=${mode} blocking=${blocking_bool}"

# ---------------------------------------------------------------------------
# Step 0 — locate or build the audit binary
# ---------------------------------------------------------------------------
preflight_log="${step_logs_dir}/step_000.log"
{
  printf '==> step 0: locate franken_evidence_manifest binary\n'
  bin="${FRANKEN_EVIDENCE_MANIFEST_BIN:-}"
  if [[ -z "$bin" ]]; then
    for cand in \
      "target_icydeer/debug/franken_evidence_manifest" \
      "target/debug/franken_evidence_manifest" \
      "target/release/franken_evidence_manifest"; do
      if [[ -x "$cand" ]]; then bin="$cand"; break; fi
    done
  fi
} >"$preflight_log" 2>&1

if [[ -z "${bin:-}" ]]; then
  echo "building franken_evidence_manifest ..." >&2
  printf 'cargo build -p frankenengine-engine --bin franken_evidence_manifest\n' >>"$commands_path"
  cargo build -p frankenengine-engine --bin franken_evidence_manifest >>"$preflight_log" 2>&1
  bin="target/debug/franken_evidence_manifest"
fi
printf 'located audit binary: %s\n' "$bin" >>"$preflight_log"
append_event "gate.preflight" "ok" "bin=${bin}"

# ---------------------------------------------------------------------------
# Step 1 — run the audit
# ---------------------------------------------------------------------------
audit_log="${step_logs_dir}/step_001.log"
printf '%s audit %s\n' "$bin" "$blocking_flag" >>"$commands_path"

set +e
"$bin" audit $blocking_flag >"$report_path" 2>"$audit_log"
audit_exit="$?"
set -e
cat "$report_path"

coverage_line="$(grep -m1 'claim-integrity-coverage' "$report_path" || true)"
overpromoted_count="$(grep -c 'OVER-PROMOTED' "$report_path" || true)"
verdict="advisory_pass"
if [[ -n "$blocking_flag" ]]; then
  verdict=$([[ "$audit_exit" -eq 0 ]] && echo "pass" || echo "fail")
fi
append_event "gate.audit" "$verdict" "exit=${audit_exit} over_promoted=${overpromoted_count}"

# ---------------------------------------------------------------------------
# Step 2 — emit trace ids + content-addressed run manifest
# ---------------------------------------------------------------------------
report_sha="$(sha256sum "$report_path" | cut -d' ' -f1)"
events_sha="$(sha256sum "$events_path" | cut -d' ' -f1)"
commands_sha="$(sha256sum "$commands_path" | cut -d' ' -f1)"
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
  --argjson blocking "${blocking_bool}" \
  --argjson audit_exit_code "${audit_exit}" \
  --arg verdict "${verdict}" \
  --arg coverage "${coverage_line}" \
  --argjson over_promoted "${overpromoted_count:-0}" \
  --arg trace_id "${trace_id}" \
  --arg git_rev "${git_rev}" \
  --arg report_sha256 "${report_sha}" \
  --arg events_sha256 "${events_sha}" \
  --arg commands_sha256 "${commands_sha}" \
  --arg owning_bead "bd-sde5e.1.3" \
  --arg capstone_bead "bd-sde5e.1.6" \
  '{
    schema_version: $schema_version,
    mode: $mode,
    blocking: $blocking,
    audit_exit_code: $audit_exit_code,
    verdict: $verdict,
    coverage: $coverage,
    over_promoted: $over_promoted,
    trace_id: $trace_id,
    git_rev: $git_rev,
    artifacts: {
      audit_report: "audit_report.txt",
      events: "events.jsonl",
      trace_ids: "trace_ids.json",
      commands: "commands.txt",
      step_logs: "step_logs"
    },
    content_hashes: {
      "audit_report.txt": $report_sha256,
      "events.jsonl": $events_sha256,
      "commands.txt": $commands_sha256
    },
    owning_bead: $owning_bead,
    capstone_bead: $capstone_bead
  }' >"$manifest_path"

append_event "gate.manifest" "ok" "report_sha256=${report_sha}"
append_event "gate.end" "$verdict" "run_dir=${run_dir}"

echo "claim_evidence_integrity_report=${report_path}"
echo "claim_evidence_integrity_manifest=${manifest_path}"
echo "claim_evidence_integrity_events=${events_path}"
echo "claim_evidence_integrity_run_dir=${run_dir}"
echo "claim_evidence_integrity_verdict=${verdict}"

# Advisory mode never fails the build; blocking mode propagates the audit exit.
if [[ -n "$blocking_flag" ]]; then
  exit "$audit_exit"
fi
exit 0
