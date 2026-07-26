#!/usr/bin/env bash
# Scheduled evidence refresh (ADR-0012 implementation note 1, BRIDGE-19.18).
#
# Runs the OBSERVED claims' real verification commands for one freshness tier and
# re-emits receipts for the ones that pass, then re-runs the claim-to-proof gate so
# the resulting freshness posture is recorded in the same session.
#
# Why sharded by tier
# -------------------
# ADR-0012 asks that "the expensive claims do not gate the cheap ones". Each tier
# is a separate invocation with its own artifact bundle and its own exit code, so
# a slow or failing shard cannot mask or delay another.
#
# Cadence is derived from the tier window rather than chosen: refreshing at about
# a quarter of the staleness window means evidence is re-verified roughly three
# times before it could expire, so a single missed run never makes a claim
# provisional.
#
#   tier       window   cadence
#   volatile     30d    weekly
#   standard     90d    monthly
#   frozen      180d    quarterly
#
# Where this can run
# ------------------
# Only where the `/dp` sibling checkouts exist, because most verification commands
# are default-feature cargo builds and the nine sibling path dependencies resolve
# even when their features are off (bd-ndpm2, bd-gw4cg). A GitHub-hosted runner has
# no `/dp`, so this script records a `skipped` outcome there rather than reporting
# a refresh that did not happen. That is the same skip-vs-fail discipline the
# cross-repo integration suite uses: "we don't know" and "we know it's broken" are
# different evidence states.
#
# Usage:  ./scripts/run_evidence_refresh_schedule.sh [volatile|standard|frozen|all]
# Exit:   0 refreshed (or honestly skipped); 1 a claim's verification REGRESSED;
#         2 usage error.

set -euo pipefail

root_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$root_dir"

tier="${1:-volatile}"
case "$tier" in
  volatile|standard|frozen|all) ;;
  -h|--help)
    sed -n '2,40p' "${BASH_SOURCE[0]}" | sed 's/^# \{0,1\}//'
    exit 0
    ;;
  *)
    echo "usage: $0 [volatile|standard|frozen|all]" >&2
    exit 2
    ;;
esac

timestamp="$(date -u +%Y%m%dT%H%M%SZ)"
artifact_root="${EVIDENCE_REFRESH_ARTIFACT_ROOT:-artifacts/evidence_refresh}"
run_dir="${artifact_root}/${timestamp}"
mkdir -p "${run_dir}/step_logs"
report_path="${run_dir}/refresh_report.json"
manifest_path="${run_dir}/manifest.json"
commands_path="${run_dir}/commands.txt"
timeout_seconds="${EVIDENCE_REFRESH_TIMEOUT_SECONDS:-1800}"

command -v jq >/dev/null 2>&1 || { echo "error: jq is required" >&2; exit 2; }

status="refreshed"
note=""

# Skip-vs-fail: a missing sibling checkout means we cannot verify, not that
# verification failed. Recording it as `skipped` keeps the two distinguishable.
declare -a missing_siblings=()
for sibling in sqlmodel_rust fastapi_rust frankenpandas; do
  [[ -d "/dp/${sibling}" ]] || missing_siblings+=("$sibling")
done

{
  echo "# evidence refresh schedule, tier=${tier}, ${timestamp}"
  echo "python3 scripts/reemit_evidence_receipts.py ${tier:+--tier ${tier}} --json ${report_path} --timeout ${timeout_seconds}"
  echo "./scripts/run_claim_to_proof_matrix_gate.sh ci"
} >"$commands_path"

refresh_exit=0
if [[ "${#missing_siblings[@]}" -gt 0 ]]; then
  status="skipped"
  note="missing sibling checkouts: ${missing_siblings[*]} (see bd-gw4cg)"
  echo "evidence_refresh=skipped tier=${tier} reason=missing_siblings:${missing_siblings[*]}" >&2
else
  tier_arg=()
  [[ "$tier" != "all" ]] && tier_arg=(--tier "$tier")
  set +e
  python3 scripts/reemit_evidence_receipts.py \
    "${tier_arg[@]}" \
    --json "$report_path" \
    --timeout "$timeout_seconds" \
    2>&1 | tee "${run_dir}/step_logs/reemit.log"
  refresh_exit="${PIPESTATUS[0]}"
  set -e

  # ADR-0012 §5: a failed verification command is a REGRESSION, never staleness.
  # The two must not share a channel, so this is reported as a distinct status and
  # is the only thing that makes the scheduled run fail.
  if [[ "$refresh_exit" -ne 0 ]]; then
    status="regression"
    note="$(jq -r '[.results[] | select(.status=="failed") | .claim_id] | join(", ")' "$report_path" 2>/dev/null || echo "see refresh_report.json")"
    echo "evidence_refresh=regression tier=${tier} claims=${note}" >&2
  fi
fi

# Re-run the claim gate so the freshness posture after this refresh is captured in
# the same bundle. Its own verdict is independent of ours.
gate_freshness="null"
if [[ "$status" != "skipped" ]]; then
  set +e
  ./scripts/run_claim_to_proof_matrix_gate.sh ci >"${run_dir}/step_logs/claim_gate.log" 2>&1
  set -e
  gate_report="$(grep -m1 '^claim_to_proof_matrix_gate_report=' "${run_dir}/step_logs/claim_gate.log" | cut -d= -f2- || true)"
  if [[ -n "$gate_report" && -f "$gate_report" ]]; then
    gate_freshness="$(jq -c '.freshness' "$gate_report")"
  fi
fi

jq -n \
  --arg schema_version "franken-engine.evidence-refresh-schedule.v1" \
  --arg tier "$tier" \
  --arg timestamp "$timestamp" \
  --arg status "$status" \
  --arg note "$note" \
  --arg owning_bead "bd-performance-conformance-bridge-tu32j.20.18" \
  --arg adr "docs/adr/ADR-0012-evidence-freshness-model.md" \
  --argjson refresh_exit "$refresh_exit" \
  --argjson freshness_after "$gate_freshness" \
  --slurpfile refresh <(cat "$report_path" 2>/dev/null || echo 'null') \
  '{
    schema_version: $schema_version,
    owning_bead: $owning_bead,
    adr: $adr,
    tier: $tier,
    generated_at_utc: $timestamp,
    status: $status,
    note: (if $note == "" then null else $note end),
    refresh_exit_code: $refresh_exit,
    refresh: ($refresh[0] // null),
    freshness_after: $freshness_after
  }' >"$manifest_path"

echo "evidence_refresh_manifest=${manifest_path}"
echo "evidence_refresh=${status} tier=${tier}"

[[ "$status" == "regression" ]] && exit 1
exit 0
