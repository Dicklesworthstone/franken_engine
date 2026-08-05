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
# Hosted-runner support
# ---------------------
# The sibling crates that once required `/dp` path checkouts are now published and
# resolved from the registry (bd-gw4cg). Do not gate execution on local checkout
# presence: an unavailable registry or a build failure must reach the verifier's
# conservative infrastructure-vs-regression classifier. The old `/dp` preflight
# caused every GitHub-hosted run to report `skipped` without executing one claim
# even after the dependency constraint had been removed (bd-pa12f).
#
# Three outcomes, not two
# -----------------------
# ADR-0012 §5.1 / bd-566x4. A non-zero verification exit is reported as `regression`
# only when the command actually reached a verdict. When it could not run at all --
# build tree deleted underneath it by a concurrent agent, disk full, timeout -- the
# status is `infrastructure` and the run does not fail. Both write no receipt, so
# the claim stays exactly as provisional either way; what differs is who is being
# asked to do something. "Audit this claim" and "fix this machine" are different
# work orders, and a job that keeps issuing the first when it means the second is a
# job people learn to ignore.
#
# Usage:  ./scripts/run_evidence_refresh_schedule.sh [volatile|standard|frozen|all]
#         EVIDENCE_REFRESH_ONLY=FE-CLAIM-024 limits a manual proof run; a
#         comma-separated list is accepted.
# Exit:   0 passed or infrastructure-blocked; 1 verification/configuration REGRESSED;
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

only="${EVIDENCE_REFRESH_ONLY:-}"
if [[ -n "$only" && ! "$only" =~ ^FE-CLAIM-[0-9]{3}(,FE-CLAIM-[0-9]{3})*$ ]]; then
  echo "error: EVIDENCE_REFRESH_ONLY must be a comma-separated list of FE-CLAIM-xxx ids" >&2
  exit 2
fi

timestamp="$(date -u +%Y%m%dT%H%M%SZ)"
artifact_root="${EVIDENCE_REFRESH_ARTIFACT_ROOT:-artifacts/evidence_refresh}"
run_dir="${artifact_root}/${timestamp}"
mkdir -p "${run_dir}/step_logs"
report_path="${run_dir}/refresh_report.json"
manifest_path="${run_dir}/manifest.json"
commands_path="${run_dir}/commands.txt"
timeout_seconds="${EVIDENCE_REFRESH_TIMEOUT_SECONDS:-1800}"

command -v jq >/dev/null 2>&1 || { echo "error: jq is required" >&2; exit 2; }

status="passed"
note=""

# Derive the exact expected selection independently of the emitter. This catches
# partial filter matches (for example FE-CLAIM-008 plus a misspelled id) and any
# future emitter bug that silently drops one claim from a scheduled tier.
if [[ -n "$only" ]]; then
  expected_claim_ids="$only"
else
  expected_claim_ids="$(jq -r --arg tier "$tier" '
    [
      .claims[]
      | select(.allowed_state == "observed")
      | select($tier == "all" or .freshness_tier == $tier)
      | .claim_id
    ]
    | sort
    | join(",")
  ' docs/claim_to_proof_matrix_v1.json)"
fi

tier_arg=()
[[ "$tier" != "all" ]] && tier_arg=(--tier "$tier")
only_arg=()
[[ -n "$only" ]] && only_arg=(--only "$only")
reemit_args=(
  "${tier_arg[@]}"
  "${only_arg[@]}"
  --json "$report_path"
  --timeout "$timeout_seconds"
)

{
  echo "# evidence refresh schedule, tier=${tier}, ${timestamp}"
  printf 'python3 scripts/reemit_evidence_receipts.py'
  printf ' %q' "${reemit_args[@]}"
  printf '\n'
  echo "./scripts/run_claim_to_proof_matrix_gate.sh ci"
} >"$commands_path"

refresh_exit=0
set +e
python3 scripts/reemit_evidence_receipts.py \
  "${reemit_args[@]}" \
  2>&1 | tee "${run_dir}/step_logs/reemit.log"
refresh_exit="${PIPESTATUS[0]}"
set -e

# ADR-0012 §5: a failed verification command is a REGRESSION, never staleness.
# The two must not share a channel, so this is reported as a distinct status and
# is the only thing that makes the scheduled run fail.
#
# ADR-0012 §5.1 (bd-566x4): there is a third outcome. reemit exits 3 when no
# claim regressed but at least one could not be verified at all -- the build tree
# was deleted underneath it, the disk filled, the command timed out. Reporting
# that as a regression sends an operator to audit a claim that was never
# implicated, and a few such false alarms are how a scheduled evidence job
# becomes something people mute. It gets its own status and does NOT fail the
# run, because there is nothing here for the owning team to fix.
if [[ "$refresh_exit" -eq 3 ]]; then
  status="infrastructure"
  note="$(jq -r '[.results[] | select(.status=="infrastructure") | "\(.claim_id) (\(.infrastructure_reason))"] | join("; ")' "$report_path" 2>/dev/null || echo "see refresh_report.json")"
  echo "evidence_refresh=infrastructure tier=${tier} blocked=${note}" >&2
elif [[ "$refresh_exit" -ne 0 ]]; then
  status="regression"
  note="$(jq -r '[.results[] | select(.status=="failed") | .claim_id] | join(", ")' "$report_path" 2>/dev/null || echo "see refresh_report.json")"
  echo "evidence_refresh=regression tier=${tier} claims=${note}" >&2
elif ! jq -e --arg expected "$expected_claim_ids" '
  if (.results | type) != "array" then
    false
  else
    .results as $results
    | [$results[].claim_id] as $actual
    | ($expected | if . == "" then [] else split(",") end) as $wanted
    | ($results | length) > 0
      and all($results[]; (.claim_id | type) == "string" and .status == "passed")
      and (($actual | length) == ($actual | unique | length))
      and (($actual | sort) == ($wanted | sort))
  end
' "$report_path" >/dev/null 2>&1; then
  # A zero exit is not sufficient evidence if no claim ran or the emitter marked
  # one as skipped, duplicated, or absent from an explicit filter. Treat that as a
  # verifier-configuration regression: the schedule promised to refresh the exact
  # selected claims and did not do so, even though no claim body failed.
  status="regression"
  note="$(jq -r --arg expected "$expected_claim_ids" '
    if (.results | type) != "array" then
      "missing or invalid results array"
    elif (.results | length) == 0 then
      "no claim was selected"
    elif any(.results[]; (.claim_id | type) != "string" or (.status | type) != "string") then
      "malformed claim result"
    elif ([.results[].claim_id] | length) != ([.results[].claim_id] | unique | length) then
      "duplicate claim results"
    elif ([.results[].claim_id] | sort) != ($expected | if . == "" then [] else split(",") end | sort) then
      "claim selection mismatch: expected=\($expected) reported=\([.results[].claim_id] | sort | join(","))"
    else
      [.results[] | select(.status != "passed") | "\(.claim_id) (\(.status))"]
      | join(", ")
    end
  ' "$report_path" 2>/dev/null || echo "missing or invalid refresh_report.json")"
  echo "evidence_refresh=regression tier=${tier} verifier_contract=${note}" >&2
fi

# Re-run the claim gate so the freshness posture after this refresh is captured in
# the same bundle. Its own verdict is independent of ours.
gate_freshness="null"
gate_exit=0
set +e
./scripts/run_claim_to_proof_matrix_gate.sh ci >"${run_dir}/step_logs/claim_gate.log" 2>&1
gate_exit="$?"
set -e
gate_report="$(grep -m1 '^claim_to_proof_matrix_gate_report=' "${run_dir}/step_logs/claim_gate.log" | cut -d= -f2- || true)"
if [[ -n "$gate_report" && -f "$gate_report" ]]; then
  gate_freshness="$(jq -c '.freshness // null' "$gate_report" 2>/dev/null || echo 'null')"
fi

jq -n \
  --arg schema_version "franken-engine.evidence-refresh-schedule.v1" \
  --arg tier "$tier" \
  --arg only "$only" \
  --arg timestamp "$timestamp" \
  --arg status "$status" \
  --arg note "$note" \
  --arg owning_bead "bd-performance-conformance-bridge-tu32j.20.18" \
  --arg adr "docs/adr/ADR-0012-evidence-freshness-model.md" \
  --argjson refresh_exit "$refresh_exit" \
  --argjson gate_exit "$gate_exit" \
  --argjson freshness_after "$gate_freshness" \
  --slurpfile refresh <(jq -c . "$report_path" 2>/dev/null || echo 'null') \
  '{
    schema_version: $schema_version,
    owning_bead: $owning_bead,
    adr: $adr,
    tier: $tier,
    claim_filter: (if $only == "" then null else ($only | split(",")) end),
    generated_at_utc: $timestamp,
    status: $status,
    note: (if $note == "" then null else $note end),
    refresh_exit_code: $refresh_exit,
    claim_gate_exit_code: $gate_exit,
    refresh: ($refresh[0] // null),
    freshness_after: $freshness_after
  }' >"$manifest_path"

echo "evidence_refresh_manifest=${manifest_path}"
echo "evidence_refresh=${status} tier=${tier}"

[[ "$status" == "regression" ]] && exit 1
exit 0
