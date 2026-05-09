#!/usr/bin/env bash
set -euo pipefail

root_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
artifact_root="${CLAIM_FRESHNESS_ARTIFACT_ROOT:-${TMPDIR:-/tmp}/franken-engine-claim-freshness}"
run_id="${CLAIM_FRESHNESS_RUN_ID:-$(date -u +%Y%m%dT%H%M%SZ)}"
run_dir="${CLAIM_FRESHNESS_RUN_DIR:-${artifact_root}/${run_id}}"
source_revision="${CLAIM_FRESHNESS_SOURCE_REVISION:-}"
now_ts="${CLAIM_FRESHNESS_NOW_TS:-$(date -u +%Y-%m-%dT%H:%M:%SZ)}"
default_max_age_days="30"
original_args=("$@")

matrix_json=""
readme_file=""
runtime_charter_file=""

usage() {
  cat >&2 <<'EOF'
Usage: ./scripts/claim_freshness_gate.sh --claim-matrix-json FILE [OPTIONS]

Emits advisory evidence-age alarms for README/operator claims. The gate is
read-only: it does not rewrite docs, create beads, run Cargo, invoke rch, or
repair artifact bundles.

Required:
  --claim-matrix-json FILE

Options:
  --readme-file FILE
  --runtime-charter-file FILE
  --source-revision REV
  --now-ts ISO8601_Z
  --max-age-days N
  --output-dir DIR

Artifacts:
  claim_freshness_report.json
  downgrade_suggestions.md
  events.jsonl
  commands.txt
  report.md

Exit codes:
  0   no blocking stale/missing/degraded observed claims
  42  one or more observed claims require downgrade/reproof
  64  invalid input
EOF
}

while [[ "$#" -gt 0 ]]; do
  case "$1" in
    --claim-matrix-json)
      matrix_json="${2:-}"
      shift 2
      ;;
    --readme-file)
      readme_file="${2:-}"
      shift 2
      ;;
    --runtime-charter-file)
      runtime_charter_file="${2:-}"
      shift 2
      ;;
    --source-revision)
      source_revision="${2:-}"
      shift 2
      ;;
    --now-ts)
      now_ts="${2:-}"
      shift 2
      ;;
    --max-age-days)
      default_max_age_days="${2:-}"
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

if [[ -z "$matrix_json" ]]; then
  printf 'missing required --claim-matrix-json\n' >&2
  usage
  exit 64
fi
if ! command -v jq >/dev/null 2>&1; then
  printf 'jq is required for claim freshness gate\n' >&2
  exit 2
fi
if [[ ! -f "$matrix_json" ]]; then
  printf 'claim matrix not found: %s\n' "$matrix_json" >&2
  exit 64
fi
if ! jq empty "$matrix_json" >/dev/null 2>&1; then
  printf 'invalid claim matrix JSON: %s\n' "$matrix_json" >&2
  exit 64
fi
if ! [[ "$default_max_age_days" =~ ^[0-9]+$ ]]; then
  printf 'invalid --max-age-days: %s\n' "$default_max_age_days" >&2
  exit 64
fi
now_epoch="$(date -u -d "$now_ts" +%s 2>/dev/null || true)"
if [[ -z "$now_epoch" ]]; then
  printf 'invalid --now-ts: %s\n' "$now_ts" >&2
  exit 64
fi
if [[ -z "$source_revision" ]]; then
  source_revision="$(git -C "$root_dir" rev-parse HEAD 2>/dev/null || printf unknown)"
fi

mkdir -p "$run_dir"
report_json="${run_dir}/claim_freshness_report.json"
downgrade_md="${run_dir}/downgrade_suggestions.md"
events_path="${run_dir}/events.jsonl"
commands_path="${run_dir}/commands.txt"
report_md="${run_dir}/report.md"
checks_jsonl="${run_dir}/claim_checks.jsonl"
report_tmp="${report_json}.tmp"

for artifact_path in "$report_json" "$downgrade_md" "$events_path" "$commands_path" "$report_md" "$checks_jsonl" "$report_tmp"; do
  if [[ -e "$artifact_path" ]]; then
    printf 'refusing to overwrite existing artifact: %s\n' "$artifact_path" >&2
    exit 73
  fi
done

: >"$events_path"
: >"$checks_jsonl"
printf './scripts/claim_freshness_gate.sh' >"$commands_path"
for arg in "${original_args[@]}"; do
  printf ' %q' "$arg" >>"$commands_path"
done
printf '\n' >>"$commands_path"

matrix_dir="$(cd "$(dirname "$matrix_json")" && pwd)"

resolve_path() {
  local path_value="$1"
  if [[ -z "$path_value" || "$path_value" == "null" ]]; then
    printf ''
  elif [[ "$path_value" = /* ]]; then
    printf '%s\n' "$path_value"
  elif [[ -e "${matrix_dir}/${path_value}" ]]; then
    printf '%s/%s\n' "$matrix_dir" "$path_value"
  else
    printf '%s/%s\n' "$root_dir" "$path_value"
  fi
}

state_rank() {
  case "$1" in
    hypothesis) printf '1\n' ;;
    target) printf '2\n' ;;
    observed) printf '3\n' ;;
    *) printf '0\n' ;;
  esac
}

parse_epoch() {
  local ts="$1"
  if [[ -z "$ts" || "$ts" == "null" ]]; then
    return 1
  fi
  date -u -d "$ts" +%s 2>/dev/null
}

artifact_manifest_for() {
  local artifact_path="$1"
  if [[ -f "$artifact_path" ]]; then
    printf '%s\n' "$artifact_path"
  elif [[ -d "$artifact_path" && -f "${artifact_path}/run_manifest.json" ]]; then
    printf '%s/run_manifest.json\n' "$artifact_path"
  elif [[ -d "$artifact_path" && -f "${artifact_path}/manifest.json" ]]; then
    printf '%s/manifest.json\n' "$artifact_path"
  else
    printf ''
  fi
}

write_event() {
  local claim_id="$1"
  local decision="$2"
  local severity="$3"
  local detail="$4"

  jq -nc \
    --arg schema_version "franken-engine.claim-freshness.event.v1" \
    --arg component "claim_freshness_gate" \
    --arg claim_id "$claim_id" \
    --arg decision "$decision" \
    --arg severity "$severity" \
    --arg detail "$detail" \
    '{
      schema_version: $schema_version,
      component: $component,
      event: "claim.checked",
      claim_id: $claim_id,
      decision: $decision,
      severity: $severity,
      detail: $detail
    }' >>"$events_path"
}

matrix_max_age="$(jq -r '.max_observed_freshness_days // .stale_threshold_days // empty' "$matrix_json")"
if [[ -z "$matrix_max_age" || "$matrix_max_age" == "null" ]]; then
  matrix_max_age="$default_max_age_days"
fi

while IFS= read -r claim; do
  claim_id="$(jq -r '.claim_id // ""' <<<"$claim")"
  source_path_raw="$(jq -r '.source_path // ""' <<<"$claim")"
  source_path="$(resolve_path "$source_path_raw")"
  if [[ -n "$readme_file" && "${source_path_raw##*/}" == "README.md" ]]; then
    source_path="$(resolve_path "$readme_file")"
  fi
  start_line="$(jq -r '.source_span.start_line // ""' <<<"$claim")"
  end_line="$(jq -r '.source_span.end_line // ""' <<<"$claim")"
  must_contain="$(jq -r '.source_span.must_contain // ""' <<<"$claim")"
  allowed_state="$(jq -r '.allowed_state // "hypothesis"' <<<"$claim")"
  actual_wording_state="$(jq -r '.actual_wording_state // "hypothesis"' <<<"$claim")"
  artifact_path_raw="$(jq -r '.artifact_path // ""' <<<"$claim")"
  artifact_path="$(resolve_path "$artifact_path_raw")"
  expected_revision="$(jq -r '.expected_source_revision // .source_revision // empty' <<<"$claim")"
  downgrade_text="$(jq -r '.downgrade_text // ""' <<<"$claim")"
  claim_max_age="$(jq -r '.max_age_days // .freshness_days // empty' <<<"$claim")"
  file_section="$(jq -r '.file_section // .section // ""' <<<"$claim")"
  if [[ -z "$claim_max_age" || "$claim_max_age" == "null" ]]; then
    claim_max_age="$matrix_max_age"
  fi

  decision="allow"
  severity="info"
  reason="claim wording is within allowed state"
  suggested_wording="$downgrade_text"
  artifact_age_days=""
  artifact_revision=""
  artifact_status=""
  artifact_manifest=""
  span_status="unchecked"
  alignment_status="unchecked"

  allowed_rank="$(state_rank "$allowed_state")"
  actual_rank="$(state_rank "$actual_wording_state")"
  if [[ "$allowed_rank" -eq 0 || "$actual_rank" -eq 0 || "$actual_rank" -gt "$allowed_rank" ]]; then
    decision="downgrade_required"
    severity="error"
    reason="claim wording state is stronger than allowed state"
  fi

  if [[ -n "$source_path_raw" ]]; then
    if [[ -f "$source_path" && "$start_line" =~ ^[0-9]+$ && "$end_line" =~ ^[0-9]+$ ]]; then
      span_text="$(sed -n "${start_line},${end_line}p" "$source_path")"
      if [[ "$span_text" == *"$must_contain"* ]]; then
        span_status="pass"
      else
        span_status="missing_required_text"
        decision="downgrade_required"
        severity="error"
        reason="source span no longer contains required claim text"
      fi
    else
      span_status="missing_source_span"
      decision="downgrade_required"
      severity="error"
      reason="source span cannot be checked"
    fi
  fi

  if [[ "$allowed_state" == "observed" || "$actual_wording_state" == "observed" ]]; then
    if [[ -z "$artifact_path_raw" || ! -e "$artifact_path" ]]; then
      decision="downgrade_required"
      severity="error"
      reason="observed claim is missing its backing artifact"
    else
      artifact_manifest="$(artifact_manifest_for "$artifact_path")"
      if [[ -z "$artifact_manifest" || ! -f "$artifact_manifest" ]]; then
        decision="downgrade_required"
        severity="error"
        reason="observed claim artifact has no readable manifest"
      elif ! jq empty "$artifact_manifest" >/dev/null 2>&1; then
        decision="downgrade_required"
        severity="error"
        reason="observed claim artifact has no readable manifest"
      else
        generated_at="$(jq -r '.generated_at_utc // .generated_utc // .freshness.generated_utc // .created_at // ""' "$artifact_manifest")"
        artifact_revision="$(jq -r '.source_revision // .code_revision // .git_revision // ""' "$artifact_manifest")"
        artifact_status="$(jq -r '.status // .decision // .verdict // .overall_outcome // "pass"' "$artifact_manifest" | tr '[:upper:]' '[:lower:]')"
        generated_epoch="$(parse_epoch "$generated_at" || true)"
        if [[ -n "$generated_epoch" ]]; then
          artifact_age_days="$(((now_epoch - generated_epoch) / 86400))"
          if [[ "$artifact_age_days" -gt "$claim_max_age" ]]; then
            decision="downgrade_required"
            severity="warning"
            reason="observed claim artifact is stale (${artifact_age_days}d > ${claim_max_age}d)"
          fi
        else
          decision="downgrade_required"
          severity="warning"
          reason="observed claim artifact age cannot be determined"
        fi
        if [[ "$artifact_status" =~ degraded|fail|failed|blocked|contaminated ]]; then
          decision="downgrade_required"
          severity="error"
          reason="observed claim artifact status is not fresh pass: ${artifact_status}"
        fi
        if [[ -n "$expected_revision" && -n "$artifact_revision" && "$artifact_revision" != "$expected_revision" ]]; then
          decision="downgrade_required"
          severity="warning"
          reason="observed claim artifact revision differs from expected revision"
        elif [[ -z "$expected_revision" && -n "$artifact_revision" && "$artifact_revision" != "$source_revision" && "$source_revision" != "unknown" ]]; then
          decision="downgrade_required"
          severity="warning"
          reason="observed claim artifact revision differs from source revision"
        fi
      fi
    fi
  elif [[ -z "$suggested_wording" ]]; then
    decision="downgrade_required"
    severity="error"
    reason="target/hypothesis claim lacks explicit suggested wording"
  fi

  if [[ -n "$runtime_charter_file" ]]; then
    charter_path="$(resolve_path "$runtime_charter_file")"
    if [[ -f "$charter_path" ]] && grep -Fq "$claim_id" "$charter_path"; then
      alignment_status="pass"
    else
      alignment_status="missing_claim_id"
      if [[ "$decision" == "allow" ]]; then
        decision="downgrade_required"
        severity="warning"
        reason="runtime charter does not reference claim id"
      fi
    fi
  fi

  if [[ "$decision" == "allow" ]]; then
    suggested_wording=""
  elif [[ -z "$suggested_wording" ]]; then
    suggested_wording="Downgrade ${claim_id} to TARGET/HYPOTHESIS wording until fresh artifact evidence is available."
  fi

  jq -nc \
    --arg claim_id "$claim_id" \
    --arg source_path "$source_path_raw" \
    --arg file_section "$file_section" \
    --arg artifact_path "$artifact_path_raw" \
    --arg artifact_manifest "$artifact_manifest" \
    --arg artifact_age_days "$artifact_age_days" \
    --arg artifact_revision "$artifact_revision" \
    --arg artifact_status "$artifact_status" \
    --arg code_revision "$source_revision" \
    --arg expected_revision "$expected_revision" \
    --arg allowed_state "$allowed_state" \
    --arg actual_wording_state "$actual_wording_state" \
    --arg decision "$decision" \
    --arg severity "$severity" \
    --arg reason "$reason" \
    --arg suggested_wording "$suggested_wording" \
    --arg span_status "$span_status" \
    --arg alignment_status "$alignment_status" \
    '{
      claim_id: $claim_id,
      file: $source_path,
      section: (if $file_section == "" then null else $file_section end),
      artifact_path: (if $artifact_path == "" then null else $artifact_path end),
      artifact_manifest: (if $artifact_manifest == "" then null else $artifact_manifest end),
      artifact_age_days: (if $artifact_age_days == "" then null else ($artifact_age_days | tonumber) end),
      artifact_revision: (if $artifact_revision == "" then null else $artifact_revision end),
      code_revision: $code_revision,
      expected_revision: (if $expected_revision == "" then null else $expected_revision end),
      artifact_status: (if $artifact_status == "" then null else $artifact_status end),
      allowed_state: $allowed_state,
      actual_wording_state: $actual_wording_state,
      source_span_status: $span_status,
      runtime_charter_alignment: $alignment_status,
      decision: $decision,
      severity: $severity,
      reason: $reason,
      suggested_wording: (if $suggested_wording == "" then null else $suggested_wording end)
    }' >>"$checks_jsonl"

  write_event "$claim_id" "$decision" "$severity" "$reason"
done < <(jq -c '.claims[]' "$matrix_json")

jq -s \
  --arg schema_version "franken-engine.claim-freshness-report.v1" \
  --arg matrix_json "$matrix_json" \
  --arg source_revision "$source_revision" \
  --arg now_ts "$now_ts" \
  --arg report_json "$report_json" \
  --arg downgrade_md "$downgrade_md" \
  --arg events_path "$events_path" \
  --arg commands_path "$commands_path" \
  --arg report_md "$report_md" \
  '
    . as $claims
    | {
        schema_version: $schema_version,
        matrix_json: $matrix_json,
        source_revision: $source_revision,
        evaluated_at: $now_ts,
        decision: (if any($claims[]; .decision == "downgrade_required") then "downgrade_required" else "pass" end),
        claim_count: ($claims | length),
        alarm_counts: {
          total: ($claims | map(select(.decision == "downgrade_required")) | length),
          errors: ($claims | map(select(.decision == "downgrade_required" and .severity == "error")) | length),
          warnings: ($claims | map(select(.decision == "downgrade_required" and .severity == "warning")) | length)
        },
        claims: $claims,
        artifact_paths: {
          claim_freshness_report_json: $report_json,
          downgrade_suggestions_md: $downgrade_md,
          events_jsonl: $events_path,
          commands_txt: $commands_path,
          report_md: $report_md
        },
        non_mutation_attestation: {
          reads_only: true,
          rewrites_docs: false,
          runs_cargo: false,
          runs_rch: false,
          creates_beads: false,
          mutates_beads: false
        }
      }
  ' "$checks_jsonl" >"$report_tmp"
mv "$report_tmp" "$report_json"

jq -r '
  "# Claim Freshness Downgrade Suggestions",
  "",
  (if (.claims | map(select(.decision == "downgrade_required")) | length) == 0 then
    "No downgrade suggestions."
  else
    (.claims[]
      | select(.decision == "downgrade_required")
      | "## " + .claim_id
        + "\n\n- File/section: `" + .file + "` / `" + (.section // "unspecified") + "`"
        + "\n- Artifact: `" + (.artifact_path // "none") + "`"
        + "\n- Artifact age: `" + ((.artifact_age_days // "unknown") | tostring) + "`"
        + "\n- Code revision: `" + .code_revision + "`"
        + "\n- Decision: `" + .decision + "`"
        + "\n- Reason: " + .reason
        + "\n\nSuggested wording:\n\n" + (.suggested_wording // "Downgrade until fresh proof is available.") + "\n")
  end)
' "$report_json" >"$downgrade_md"

jq -r '
  "# Claim Freshness Report",
  "",
  ("- Decision: `" + .decision + "`"),
  ("- Claims: `" + (.claim_count | tostring) + "`"),
  ("- Alarms: `" + (.alarm_counts.total | tostring) + "`"),
  "",
  "## Claim Decisions",
  "",
  (.claims[]
    | "- `" + .claim_id + "` `" + .decision + "` `" + .reason + "`")
' "$report_json" >"$report_md"

printf 'claim_freshness_report=%s\n' "$report_json"
printf 'claim_freshness_downgrade_suggestions=%s\n' "$downgrade_md"
printf 'claim_freshness_events=%s\n' "$events_path"

if jq -e '.decision == "downgrade_required"' "$report_json" >/dev/null; then
  exit 42
fi
exit 0
