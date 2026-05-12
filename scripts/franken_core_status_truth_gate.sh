#!/usr/bin/env bash
set -euo pipefail

root_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
artifact_root="${FRANKEN_CORE_STATUS_TRUTH_ARTIFACT_ROOT:-${TMPDIR:-/tmp}/franken-core-status-truth-gate}"
run_id="${FRANKEN_CORE_STATUS_TRUTH_RUN_ID:-$(date -u +%Y%m%dT%H%M%SZ)}"
run_dir="${FRANKEN_CORE_STATUS_TRUTH_RUN_DIR:-${artifact_root}/${run_id}}"
root_cargo="${root_dir}/Cargo.toml"
core_cargo="${root_dir}/crates/franken-core/Cargo.toml"
source_revision="${FRANKEN_CORE_STATUS_TRUTH_SOURCE_REVISION:-}"
declare -a claim_files=()
original_args=("$@")

usage() {
  cat >&2 <<'EOF'
Usage: ./scripts/franken_core_status_truth_gate.sh [OPTIONS]

Options:
  --root-cargo PATH
  --core-cargo PATH
  --claim-file PATH        May be repeated. Defaults to canonical live docs.
  --source-revision REV
  --output-dir DIR

The gate is read-only. It writes truth_report.json, events.jsonl,
commands.txt, and report.md. It exits 42 when status claims fail closed.
EOF
}

repo_relative_path() {
  local path="$1"
  if [[ "$path" = /* ]]; then
    realpath --relative-to="$root_dir" "$path" 2>/dev/null || printf '%s\n' "$path"
  else
    printf '%s\n' "${path#./}"
  fi
}

while [[ "$#" -gt 0 ]]; do
  case "$1" in
    --root-cargo)
      root_cargo="${2:-}"
      shift 2
      ;;
    --core-cargo)
      core_cargo="${2:-}"
      shift 2
      ;;
    --claim-file)
      claim_files+=("${2:-}")
      shift 2
      ;;
    --source-revision)
      source_revision="${2:-}"
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
      printf 'unknown option: %s\n' "$1" >&2
      usage
      exit 64
      ;;
  esac
done

if [[ -z "$source_revision" ]]; then
  source_revision="$(git -C "$root_dir" rev-parse --short HEAD 2>/dev/null || printf unknown)"
fi

if [[ "${#claim_files[@]}" -eq 0 ]]; then
  claim_files=(
    "${root_dir}/Cargo.toml"
    "${root_dir}/crates/franken-core/README.md"
    "${root_dir}/docs/FRANKEN_CORE_GRADUATION_CONTRACT_V1.md"
    "${root_dir}/docs/franken_core_graduation_contract_v1.json"
    "${root_dir}/docs/FRANKEN_CORE_API_PARITY_LEDGER_V1.md"
    "${root_dir}/docs/franken_core_api_parity_ledger_v1.json"
    "${root_dir}/docs/FRANKEN_CORE_VALIDATION_IMPACT_PLANNER_V1.md"
    "${root_dir}/docs/franken_core_validation_impact_planner_v1.json"
    "${root_dir}/docs/FRANKEN_CORE_STATUS_TRUTH_GATE_V1.md"
    "${root_dir}/docs/franken_core_status_truth_gate_v1.json"
    "${root_dir}/docs/FRANKEN_CORE_NO_MOCK_GRADUATION_DRILL_V1.md"
    "${root_dir}/docs/franken_core_no_mock_graduation_drill_v1.json"
    "${root_dir}/docs/FRANKEN_CORE_STAGED_INCLUSION_REHEARSAL_V1.md"
    "${root_dir}/docs/franken_core_staged_inclusion_rehearsal_v1.json"
  )
fi

mkdir -p "$run_dir"
report_json="${run_dir}/truth_report.json"
events_path="${run_dir}/events.jsonl"
commands_path="${run_dir}/commands.txt"
report_md="${run_dir}/report.md"
violations_jsonl="${run_dir}/violations.jsonl"
claim_files_json="${run_dir}/claim_files.json"

: >"$events_path"
: >"$violations_jsonl"

printf './scripts/franken_core_status_truth_gate.sh' >"$commands_path"
for arg in "${original_args[@]}"; do
  printf ' %q' "$arg" >>"$commands_path"
done
printf '\n' >>"$commands_path"

printf '%s\n' "${claim_files[@]}" | jq -R . | jq -s 'map(select(length > 0))' >"$claim_files_json"

write_event() {
  jq -nc \
    --arg schema_version "franken-engine.franken-core-status-truth-gate.event.v1" \
    --arg event "$1" \
    --arg outcome "$2" \
    --arg detail "$3" \
    --arg source_revision "$source_revision" \
    '{schema_version:$schema_version,event:$event,outcome:$outcome,detail:$detail,source_revision:$source_revision}' >>"$events_path"
}

append_violation() {
  local code="$1"
  local path="$2"
  local line_number="$3"
  local snippet="$4"
  local remediation="$5"

  jq -nc \
    --arg code "$code" \
    --arg path "$(repo_relative_path "$path")" \
    --argjson line_number "$line_number" \
    --arg snippet "$snippet" \
    --arg remediation "$remediation" \
    '{code:$code,path:$path,line_number:$line_number,snippet:$snippet,remediation:$remediation}' >>"$violations_jsonl"
}

toml_array_contains() {
  local file="$1"
  local key="$2"
  local value="$3"
  awk -v key="$key" -v value="$value" '
    BEGIN { state = 0; found = 0; closed = 0 }
    {
      line = $0
      sub(/[[:space:]]*#.*/, "", line)
      if (state == 0 && line ~ "^[[:space:]]*" key "[[:space:]]*=") {
        state = 1
      }
      if (state == 1) {
        if (index(line, "\"" value "\"") > 0) {
          found = 1
        }
        if (index(line, "]") > 0) {
          closed = 1
          exit
        }
      }
    }
    END {
      if (state == 0) {
        print "missing"
      } else if (closed == 0) {
        print "malformed"
      } else if (found == 1) {
        print "true"
      } else {
        print "false"
      }
    }
  ' "$file"
}

core_package_state() {
  local file="$1"
  if [[ ! -f "$file" ]]; then
    printf 'missing\n'
    return
  fi
  if awk '
    BEGIN { in_package = 0; found = 0 }
    /^\[package\][[:space:]]*$/ { in_package = 1; next }
    /^\[/ && in_package == 1 { in_package = 0 }
    in_package == 1 && /^[[:space:]]*name[[:space:]]*=[[:space:]]*"frankenengine-core"[[:space:]]*$/ { found = 1 }
    END { exit(found ? 0 : 1) }
  ' "$file"; then
    printf 'present\n'
  else
    printf 'malformed\n'
  fi
}

line_mentions_core() {
  local lower="$1"
  [[ "$lower" == *"franken-core"* || "$lower" == *"franken_core"* || "$lower" == *"frankenengine-core"* ]]
}

line_has_stale_underclaim() {
  local lower="$1"
  [[ "$lower" == *"reference-only"* ||
     "$lower" == *"reference only"* ||
     "$lower" == *"documentation-only exclusion"* ||
     "$lower" == *"missing-module"* ||
     "$lower" == *"missing module"* ||
     "$lower" == *"not compileable"* ||
     "$lower" == *"does not compile"* ||
     "$lower" == *"cannot compile"* ]]
}

file_has_superseding_context() {
  local lower="$1"
  [[ "$lower" == *"bd-zsais"* ||
     "$lower" == *"bd-dymfz"* ||
     "$lower" == *"bd-nwhcp"* ||
     "$lower" == *"superseded"* ||
     "$lower" == *"standalone compileability"* ||
     "$lower" == *"standalone manifest compileable"* ||
     "$lower" == *"standalone manifest is compileable"* ]]
}

line_has_overclaim() {
  local lower="$1"
  [[ "$lower" == *"workspace-ready"* ||
     "$lower" == *"workspace ready"* ||
     "$lower" == *"included in the workspace"* ||
     "$lower" == *"included in workspace"* ||
     "$lower" == *"workspace member"* ||
     "$lower" == *"workspace inclusion complete"* ||
     "$lower" == *"workspace inclusion is complete"* ||
     "$lower" == *"graduation complete"* ||
     "$lower" == *"ready for workspace inclusion"* ]]
}

line_negates_overclaim() {
  local lower="$1"
  [[ "$lower" == *"not "* ||
     "$lower" == *"must not"* ||
     "$lower" == *"false"* ||
     "$lower" == *"blocked"* ||
     "$lower" == *"unapproved"* ||
     "$lower" == *"until"* ||
     "$lower" == *"do not"* ||
     "$lower" == *"does not"* ||
     "$lower" == *"without claiming"* ||
     "$lower" == *"without claiming workspace"* ||
     "$lower" == *"over-eager claims"* ||
     "$lower" == *"considered for"* ||
     "$lower" == *"model"* ||
     "$lower" == *"optional"* ||
     "$lower" == *"remains excluded"* ||
     "$lower" == *"separate follow-up"* ||
     "$lower" == *"not sufficient"* ||
     "$lower" == *"not approve"* ]]
}

line_has_excluded_claim() {
  local lower="$1"
  [[ "$lower" == *"excluded from the workspace"* ||
     "$lower" == *"remains excluded"* ||
     "$lower" == *"still excludes"* ||
     "$lower" == *"root workspace explicitly excludes"* ||
     "$lower" == *"current_workspace_state"* && "$lower" == *"excluded"* ||
     "$lower" == *"workspace_excluded"* ||
     "$lower" == *"remain_excluded"* ||
     "$lower" == *"exclude"* && "$lower" == *"crates/franken-core"* ]]
}

line_has_standalone_compileability_claim() {
  local lower="$1"
  [[ "$lower" == *"standalone manifest compileable"* ||
     "$lower" == *"standalone manifest is compileable"* ||
     "$lower" == *"standalone compileability"* ||
     "$lower" == *"standalone manifest is expected to compile"* ||
     "$lower" == *"standalone"* && "$lower" == *"compileable"* ||
     "$lower" == *"standalone"* && "$lower" == *"compile"* ]]
}

write_event "truth_gate_start" "started" "checking franken-core status claims"

if [[ ! -f "$root_cargo" ]]; then
  append_violation \
    "root_manifest_state_contradicts_excluded_contract" \
    "$root_cargo" \
    0 \
    "root Cargo.toml missing" \
    "Restore a root Cargo.toml that excludes crates/franken-core until bd-4w7h9.8 passes."
  members_contains_core="missing"
  exclude_contains_core="missing"
else
  members_contains_core="$(toml_array_contains "$root_cargo" "members" "crates/franken-core")"
  exclude_contains_core="$(toml_array_contains "$root_cargo" "exclude" "crates/franken-core")"
fi

core_state="$(core_package_state "$core_cargo")"
if [[ "$core_state" != "present" ]]; then
  append_violation \
    "core_manifest_missing_or_malformed" \
    "$core_cargo" \
    0 \
    "core manifest state: ${core_state}" \
    "Keep crates/franken-core/Cargo.toml present with package name frankenengine-core while documenting standalone compileability."
fi

root_workspace_state="unknown"
if [[ "$exclude_contains_core" == "true" && "$members_contains_core" == "false" ]]; then
  root_workspace_state="excluded_standalone"
elif [[ "$members_contains_core" == "true" && "$exclude_contains_core" == "false" ]]; then
  root_workspace_state="included"
elif [[ "$members_contains_core" == "true" && "$exclude_contains_core" == "true" ]]; then
  root_workspace_state="contradictory_member_and_exclude"
else
  root_workspace_state="unclassified"
fi

if [[ "$root_workspace_state" != "excluded_standalone" ]]; then
  append_violation \
    "root_manifest_state_contradicts_excluded_contract" \
    "$root_cargo" \
    0 \
    "members contains crates/franken-core: ${members_contains_core}; exclude contains crates/franken-core: ${exclude_contains_core}" \
    "Either keep crates/franken-core excluded until bd-4w7h9.8 passes, or update the graduation contract and topology evidence in the same approved topology bead."
fi

has_excluded_claim=false
has_standalone_compileability_claim=false

while IFS= read -r claim_file; do
  if [[ ! -f "$claim_file" ]]; then
    append_violation \
      "missing_excluded_status_claim" \
      "$claim_file" \
      0 \
      "claim file missing" \
      "Restore the status claim file or remove it from the truth-gate input list."
    continue
  fi

  file_lower="$(tr '[:upper:]' '[:lower:]' <"$claim_file")"
  line_number=0
  previous_lower=""
  while IFS= read -r line || [[ -n "$line" ]]; do
    line_number=$((line_number + 1))
    lower="${line,,}"
    combined_lower="${previous_lower} ${lower}"

    if line_has_excluded_claim "$lower"; then
      has_excluded_claim=true
    fi
    if line_has_standalone_compileability_claim "$lower"; then
      has_standalone_compileability_claim=true
    fi

    if line_mentions_core "$lower" && line_has_stale_underclaim "$lower" && ! file_has_superseding_context "$file_lower"; then
      append_violation \
        "stale_reference_only_claim" \
        "$claim_file" \
        "$line_number" \
        "$line" \
        "Say crates/franken-core remains excluded but standalone compileability was restored by bd-zsais, bd-dymfz, and bd-nwhcp; do not repeat the old reference-only/missing-module state as current."
    fi

    if line_mentions_core "$lower" && line_has_overclaim "$lower" && ! line_negates_overclaim "$combined_lower"; then
      append_violation \
        "workspace_inclusion_overclaim" \
        "$claim_file" \
        "$line_number" \
        "$line" \
        "Replace workspace-ready/included wording with: crates/franken-core remains excluded until bd-4w7h9.8 passes and a separate topology bead changes Cargo.toml."
    fi
    previous_lower="$lower"
  done <"$claim_file"
done < <(jq -r '.[]' "$claim_files_json")

if [[ "$has_excluded_claim" != "true" ]]; then
  append_violation \
    "missing_excluded_status_claim" \
    "$claim_files_json" \
    0 \
    "no canonical excluded-status claim found" \
    "Add explicit wording that crates/franken-core remains excluded from the root workspace."
fi

if [[ "$has_standalone_compileability_claim" != "true" ]]; then
  append_violation \
    "missing_standalone_compileability_claim" \
    "$claim_files_json" \
    0 \
    "no standalone compileability claim found" \
    "Add explicit wording that crates/franken-core has a standalone compileable manifest while workspace graduation remains blocked."
fi

violation_count="$(jq -s 'length' "$violations_jsonl")"
decision="pass"
if [[ "$violation_count" -ne 0 ]]; then
  decision="fail_closed"
fi

violations_json="$(jq -s 'sort_by(.code, .path, .line_number)' "$violations_jsonl")"
reason_codes_json="$(jq -s '[.[].code] | unique | sort' "$violations_jsonl")"

jq -n \
  --arg schema_version "franken-engine.franken-core-status-truth-report.v1" \
  --arg source_revision "$source_revision" \
  --arg decision "$decision" \
  --arg root_workspace_state "$root_workspace_state" \
  --arg members_contains_core "$members_contains_core" \
  --arg exclude_contains_core "$exclude_contains_core" \
  --arg core_manifest_state "$core_state" \
  --argjson claim_files "$(cat "$claim_files_json")" \
  --argjson reason_codes "$reason_codes_json" \
  --argjson violations "$violations_json" \
  --argjson violation_count "$violation_count" \
  --arg report_json "$report_json" \
  --arg events_path "$events_path" \
  --arg commands_path "$commands_path" \
  --arg report_md "$report_md" \
  '{
    schema_version: $schema_version,
    source_revision: $source_revision,
    decision: $decision,
    root_workspace_state: $root_workspace_state,
    manifest_state: {
      members_contains_crates_franken_core: $members_contains_core,
      exclude_contains_crates_franken_core: $exclude_contains_core,
      core_manifest_state: $core_manifest_state
    },
    canonical_truth: {
      current_state: "excluded_but_standalone_compileable",
      workspace_graduation_complete: false,
      workspace_acceptance_required: "bd-4w7h9.8"
    },
    evidence_beads: [
      {bead_id:"bd-ucemx", role:"historical missing-module/reference-only context"},
      {bead_id:"bd-zsais", role:"standalone manifest compileability restored"},
      {bead_id:"bd-dymfz", role:"standalone franken-core test baseline restored"},
      {bead_id:"bd-nwhcp", role:"executable timer regressions restored"},
      {bead_id:"bd-4w7h9.8", role:"required final acceptance suite"}
    ],
    claim_files: $claim_files,
    reason_codes: $reason_codes,
    violation_count: $violation_count,
    violations: $violations,
    non_mutation_attestation: {
      rewrites_docs: false,
      edits_manifests: false,
      runs_cargo: false,
      runs_rch: false,
      creates_beads: false
    },
    artifact_paths: {
      truth_report_json: $report_json,
      events_jsonl: $events_path,
      commands_txt: $commands_path,
      report_md: $report_md
    }
  }' >"$report_json"

jq -nc \
  --arg schema_version "franken-engine.franken-core-status-truth-gate.event.v1" \
  --arg event "truth_gate_complete" \
  --arg outcome "$decision" \
  --arg detail "franken-core status truth report emitted" \
  --arg source_revision "$source_revision" \
  '{schema_version:$schema_version,event:$event,outcome:$outcome,detail:$detail,source_revision:$source_revision}' >>"$events_path"

{
  printf '# Franken-Core Status Truth Gate\n\n'
  printf -- '- decision: `%s`\n' "$decision"
  printf -- '- root_workspace_state: `%s`\n' "$root_workspace_state"
  printf -- '- violation_count: `%s`\n' "$violation_count"
  printf '\n'
  if [[ "$violation_count" -eq 0 ]]; then
    printf 'No status contradictions found.\n'
  else
    jq -r '.violations[] | "- " + .code + " at " + .path + ":" + (.line_number|tostring) + " - " + .remediation' "$report_json"
  fi
} >"$report_md"

{
  printf 'canonical remediation text:\n'
  printf 'crates/franken-core remains excluded from the root workspace, while its standalone manifest is compileable. The old reference-only/missing-module state is superseded by bd-zsais, bd-dymfz, and bd-nwhcp. Workspace graduation remains blocked until bd-4w7h9.8 passes.\n'
} >>"$commands_path"

if [[ "$decision" == "fail_closed" ]]; then
  exit 42
fi
exit 0
