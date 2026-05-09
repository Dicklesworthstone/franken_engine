#!/usr/bin/env bash
set -euo pipefail

root_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
artifact_root="${SWARM_PROOF_COMMAND_PREFLIGHT_ARTIFACT_ROOT:-${TMPDIR:-/tmp}/franken-engine-swarm-proof-command-preflight}"
run_id="${SWARM_PROOF_COMMAND_PREFLIGHT_RUN_ID:-$(date -u +%Y%m%dT%H%M%SZ)}"
run_dir="${SWARM_PROOF_COMMAND_PREFLIGHT_RUN_DIR:-${artifact_root}/${run_id}}"
original_args=("$@")

command_text=""
command_json=""
case_id=""
source_revision="${SWARM_PROOF_COMMAND_PREFLIGHT_SOURCE_REVISION:-}"
bead_id="bd-proof-command-preflight"
evidence_requires_visibility="false"

usage() {
  cat >&2 <<'EOF'
Usage: ./scripts/swarm_proof_command_preflight.sh [OPTIONS]

Cheaply classify proof command text before a proof broker considers scheduling
or reusing it. The preflight never executes the command under inspection.

Options:
  --command TEXT                 Command text to classify.
  --command-json FILE            JSON fixture with command/context fields.
  --case-id ID                   Optional deterministic case id.
  --bead-id ID                   Bead id used for safe target-dir guidance.
  --source-revision REV          Source revision recorded in artifacts.
  --evidence-requires-visibility Require RCH_VISIBILITY in RCH proof commands.
  --output-dir DIR               Artifact directory.

Artifacts:
  preflight_report.json
  run_manifest.json
  events.jsonl
  commands.txt
  report.md
EOF
}

while [[ "$#" -gt 0 ]]; do
  case "$1" in
    --command)
      command_text="${2:-}"
      shift 2
      ;;
    --command-json)
      command_json="${2:-}"
      shift 2
      ;;
    --case-id)
      case_id="${2:-}"
      shift 2
      ;;
    --bead-id)
      bead_id="${2:-}"
      shift 2
      ;;
    --source-revision)
      source_revision="${2:-}"
      shift 2
      ;;
    --evidence-requires-visibility)
      evidence_requires_visibility="true"
      shift
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

if ! command -v jq >/dev/null 2>&1; then
  printf 'jq is required for swarm proof command preflight\n' >&2
  exit 2
fi

if [[ -n "$command_json" ]]; then
  if [[ ! -f "$command_json" ]]; then
    printf 'command JSON not found: %s\n' "$command_json" >&2
    exit 64
  fi
  if ! jq empty "$command_json" >/dev/null 2>&1; then
    printf 'invalid command JSON: %s\n' "$command_json" >&2
    exit 64
  fi

  if [[ -z "$command_text" ]]; then
    command_text="$(jq -r '.command // .validation_command // ""' "$command_json")"
  fi
  if [[ -z "$case_id" ]]; then
    case_id="$(jq -r '.case_id // ""' "$command_json")"
  fi
  if [[ "$bead_id" == "bd-proof-command-preflight" ]]; then
    bead_id="$(jq -r '.context.bead_id // .bead_id // "bd-proof-command-preflight"' "$command_json")"
  fi
  if [[ "$evidence_requires_visibility" == "false" ]]; then
    evidence_requires_visibility="$(jq -r '.context.evidence_requires_visibility // .evidence_requires_visibility // false' "$command_json")"
  fi
fi

if [[ -z "$case_id" ]]; then
  case_id="manual"
fi
if [[ -z "$source_revision" ]]; then
  source_revision="$(git -C "$root_dir" rev-parse --short HEAD 2>/dev/null || printf unknown)"
fi

mkdir -p "$run_dir"
preflight_path="${run_dir}/preflight_report.json"
preflight_tmp="${preflight_path}.tmp"
manifest_path="${run_dir}/run_manifest.json"
manifest_tmp="${manifest_path}.tmp"
events_path="${run_dir}/events.jsonl"
commands_path="${run_dir}/commands.txt"
report_path="${run_dir}/report.md"

for artifact_path in \
  "$preflight_path" \
  "$preflight_tmp" \
  "$manifest_path" \
  "$manifest_tmp" \
  "$events_path" \
  "$commands_path" \
  "$report_path"; do
  if [[ -e "$artifact_path" ]]; then
    printf 'refusing to overwrite existing artifact: %s\n' "$artifact_path" >&2
    exit 73
  fi
done

: >"$events_path"
printf './scripts/swarm_proof_command_preflight.sh' >"$commands_path"
for arg in "${original_args[@]}"; do
  printf ' %q' "$arg" >>"$commands_path"
done
printf '\n' >>"$commands_path"

write_event() {
  local event="$1"
  local outcome="$2"
  local detail="$3"

  jq -nc \
    --arg schema_version "franken-engine.swarm-proof-command-preflight.event.v1" \
    --arg component "swarm_proof_command_preflight" \
    --arg event "$event" \
    --arg outcome "$outcome" \
    --arg detail "$detail" \
    --arg case_id "$case_id" \
    '{
      schema_version: $schema_version,
      component: $component,
      event: $event,
      outcome: $outcome,
      detail: $detail,
      case_id: $case_id
    }' >>"$events_path"
}

safe_token() {
  tr -c '[:alnum:]' '_' <<<"$1" | sed -E 's/_+$//; s/^_+//'
}

array_to_json() {
  if [[ "$#" -eq 0 ]]; then
    printf '[]\n'
    return 0
  fi
  printf '%s\n' "$@" | jq -R . | jq -s .
}

is_allowed_env() {
  case "$1" in
    CARGO_TARGET_DIR|CARGO_INCREMENTAL|CARGO_BUILD_JOBS|CARGO_PROFILE_DEV_DEBUG|RCH_VISIBILITY|RCH_PRIORITY|RCH_DAEMON_WAIT_RESPONSE_TIMEOUT_SECS|RUSTFLAGS|RUSTUP_TOOLCHAIN)
      return 0
      ;;
    *)
      return 1
      ;;
  esac
}

join_by_comma() {
  local IFS=', '
  printf '%s' "$*"
}

normalize_command() {
  tr '\n\t' '  ' <<<"$1" | sed -E 's/[[:space:]]+/ /g; s/^ //; s/ $//'
}

normalized_command="$(normalize_command "$command_text")"
safe_bead="$(safe_token "$bead_id")"
safe_target_dir="/tmp/rch_target_franken_engine_${safe_bead}"
safe_env_prefix="CARGO_TARGET_DIR=${safe_target_dir} CARGO_INCREMENTAL=0 CARGO_BUILD_JOBS=1"
if [[ "$evidence_requires_visibility" == "true" ]]; then
  safe_env_prefix="${safe_env_prefix} RCH_VISIBILITY=verbose"
fi

command_kind="unknown"
if [[ "$normalized_command" =~ (^|[[:space:]])cargo[[:space:]]+test([[:space:]]|$) ]]; then
  command_kind="cargo_test"
elif [[ "$normalized_command" =~ (^|[[:space:]])cargo[[:space:]]+check([[:space:]]|$) ]]; then
  command_kind="cargo_check"
elif [[ "$normalized_command" =~ (^|[[:space:]])cargo[[:space:]]+clippy([[:space:]]|$) ]]; then
  command_kind="cargo_clippy"
elif [[ "$normalized_command" =~ (^|[[:space:]])cargo[[:space:]]+build([[:space:]]|$) ]]; then
  command_kind="cargo_build"
elif [[ "$normalized_command" =~ (^|[[:space:]])cargo[[:space:]]+run([[:space:]]|$) ]]; then
  command_kind="cargo_run"
elif [[ "$normalized_command" =~ (^|[[:space:]])cargo[[:space:]]+bench([[:space:]]|$) ]]; then
  command_kind="cargo_bench"
elif [[ "$normalized_command" =~ ^git[[:space:]]+diff[[:space:]]+--check([[:space:]]|$) ]]; then
  command_kind="git_diff_check"
elif [[ "$normalized_command" =~ ^jq[[:space:]] ]]; then
  command_kind="jq"
elif [[ "$normalized_command" =~ ^bash[[:space:]]+-n([[:space:]]|$) ]]; then
  command_kind="bash_syntax"
elif [[ "$normalized_command" =~ ^shellcheck[[:space:]] ]]; then
  command_kind="shellcheck"
fi

heavy_cargo="false"
if [[ "$command_kind" =~ ^cargo_(test|check|clippy|build|run|bench)$ ]]; then
  heavy_cargo="true"
fi

transport="unknown"
if [[ "$normalized_command" =~ ^rch[[:space:]]+exec[[:space:]]+--[[:space:]]+env[[:space:]] ]]; then
  transport="rch_direct_env"
elif [[ "$normalized_command" =~ ^rch[[:space:]]+exec[[:space:]]+--([[:space:]]|$) ]]; then
  transport="rch_direct_no_env"
elif [[ "$normalized_command" =~ ^(bash|sh|zsh)[[:space:]]+-(lc|c)[[:space:]] ]]; then
  transport="shell_wrapper"
elif [[ "$normalized_command" =~ ^cargo[[:space:]] ]]; then
  transport="local_bare"
elif [[ "$heavy_cargo" == "false" && "$command_kind" != "unknown" ]]; then
  transport="read_only"
fi

cargo_suffix=""
if [[ "$normalized_command" =~ cargo[[:space:]].* ]]; then
  cargo_suffix="${BASH_REMATCH[0]}"
  cargo_suffix="${cargo_suffix%\"}"
  cargo_suffix="${cargo_suffix%\'}"
  cargo_suffix="${cargo_suffix%;}"
fi

pasteable_command=""
if [[ -n "$cargo_suffix" ]]; then
  pasteable_command="rch exec -- env ${safe_env_prefix} ${cargo_suffix}"
fi

declare -a env_assignments=()
declare -a unsupported_env=()
if [[ "$transport" == "rch_direct_env" && "$normalized_command" == *" cargo "* ]]; then
  env_segment="${normalized_command#rch exec -- env }"
  env_segment="${env_segment%% cargo *}"
  for token in $env_segment; do
    if [[ "$token" == *=* ]]; then
      env_name="${token%%=*}"
      env_assignments+=("$env_name")
      if ! is_allowed_env "$env_name"; then
        unsupported_env+=("$env_name")
      fi
    fi
  done
fi

has_target_dir="false"
if [[ "$normalized_command" == *"CARGO_TARGET_DIR="* ]]; then
  has_target_dir="true"
fi
has_visibility="false"
if [[ "$normalized_command" == *"RCH_VISIBILITY="* ]]; then
  has_visibility="true"
fi

decision="needs_human_review"
reason_code="unknown_command_shape"
remediation="Command shape is not recognized by the proof broker preflight; request human review and do not reuse it as green proof."
exit_code=42

if [[ -z "$normalized_command" ]]; then
  reason_code="missing_command"
  remediation="Provide command text before the proof broker tries to classify or reuse proof evidence."
elif [[ "$transport" == "shell_wrapper" && "$heavy_cargo" == "true" ]]; then
  decision="proof_unsafe"
  reason_code="shell_wrapper_fallback_risk"
  remediation="Remove the shell wrapper and run the command as direct argv: ${pasteable_command}"
elif [[ "$transport" == "local_bare" && "$heavy_cargo" == "true" ]]; then
  decision="proof_unsafe"
  reason_code="bare_cargo_not_allowed"
  remediation="Do not use bare Cargo for proof. Run through RCH with an isolated target dir: ${pasteable_command}"
elif [[ "$heavy_cargo" == "false" && "$transport" == "read_only" ]]; then
  decision="non_heavy_read_only"
  reason_code="non_heavy_read_only"
  pasteable_command="$normalized_command"
  remediation="Command is non-heavy/read-only; it may be used as lightweight evidence without RCH or Cargo execution."
  exit_code=0
elif [[ "$heavy_cargo" == "true" && ( "$transport" == "rch_direct_env" || "$transport" == "rch_direct_no_env" ) ]]; then
  if [[ "$has_target_dir" != "true" ]]; then
    decision="proof_unsafe"
    reason_code="missing_target_dir_policy"
    remediation="Add an isolated target dir before scheduling proof: ${pasteable_command}"
  elif [[ "${#unsupported_env[@]}" -gt 0 ]]; then
    decision="proof_unsafe"
    reason_code="unsupported_env_leakage"
    remediation="Remove unsupported env assignments ($(join_by_comma "${unsupported_env[@]}")) and use the allowlisted shape: ${pasteable_command}"
  elif [[ "$evidence_requires_visibility" == "true" && "$has_visibility" != "true" ]]; then
    decision="proof_unsafe"
    reason_code="missing_rch_visibility"
    remediation="Add RCH_VISIBILITY=verbose for evidence capture before scheduling proof: ${pasteable_command}"
  else
    decision="proof_safe"
    reason_code="direct_rch_cargo_proof"
    pasteable_command="$normalized_command"
    remediation="Command is preflight-safe; preserve the direct rch exec -- env shape, CARGO_TARGET_DIR, and env allowlist when scheduling proof."
    exit_code=0
  fi
elif [[ "$heavy_cargo" == "true" ]]; then
  decision="proof_unsafe"
  reason_code="unsupported_heavy_command_shape"
  remediation="Normalize the heavy proof command into direct RCH argv before scheduling: ${pasteable_command}"
fi

env_assignments_json="$(array_to_json "${env_assignments[@]}")"
unsupported_env_json="$(array_to_json "${unsupported_env[@]}")"

write_event "preflight.started" "ok" "$case_id"

jq -n \
  --arg schema_version "franken-engine.swarm-proof-command-preflight.v1" \
  --arg case_id "$case_id" \
  --arg bead_id "$bead_id" \
  --arg source_revision "$source_revision" \
  --arg command "$command_text" \
  --arg normalized_command "$normalized_command" \
  --arg command_kind "$command_kind" \
  --arg transport "$transport" \
  --arg decision "$decision" \
  --arg reason_code "$reason_code" \
  --arg remediation "$remediation" \
  --arg pasteable_command "$pasteable_command" \
  --arg safe_target_dir "$safe_target_dir" \
  --argjson env_assignments "$env_assignments_json" \
  --argjson unsupported_env "$unsupported_env_json" \
  --arg evidence_requires_visibility "$evidence_requires_visibility" \
  --arg has_target_dir "$has_target_dir" \
  --arg has_visibility "$has_visibility" \
  --arg heavy_cargo "$heavy_cargo" \
  --arg preflight_path "$preflight_path" \
  --arg manifest_path "$manifest_path" \
  --arg events_path "$events_path" \
  --arg commands_path "$commands_path" \
  --arg report_path "$report_path" \
  '{
    schema_version: $schema_version,
    case_id: $case_id,
    bead_id: $bead_id,
    source_revision: $source_revision,
    decision: $decision,
    reason_code: $reason_code,
    command: {
      raw: $command,
      normalized: $normalized_command,
      command_kind: $command_kind,
      transport: $transport,
      heavy_cargo: ($heavy_cargo == "true"),
      env_assignments: $env_assignments,
      unsupported_env: $unsupported_env,
      has_target_dir: ($has_target_dir == "true"),
      evidence_requires_visibility: ($evidence_requires_visibility == "true"),
      has_visibility: ($has_visibility == "true")
    },
    remediation: $remediation,
    pasteable_command: (if $pasteable_command == "" then null else $pasteable_command end),
    safe_target_dir: $safe_target_dir,
    non_mutation_attestation: {
      runs_cargo: false,
      runs_rch: false,
      mutates_br: false,
      sends_agent_mail: false,
      mutates_remote_workers: false,
      changes_live_queue_policy: false
    },
    artifact_paths: {
      preflight_report_json: $preflight_path,
      run_manifest_json: $manifest_path,
      events_jsonl: $events_path,
      commands_txt: $commands_path,
      report_md: $report_path
    }
  }' >"$preflight_tmp"
mv "$preflight_tmp" "$preflight_path"

jq -n \
  --arg schema_version "franken-engine.swarm-proof-command-preflight-run-manifest.v1" \
  --arg component "swarm_proof_command_preflight" \
  --arg case_id "$case_id" \
  --arg source_revision "$source_revision" \
  --arg decision "$decision" \
  --arg reason_code "$reason_code" \
  --arg preflight_path "$preflight_path" \
  '{
    schema_version: $schema_version,
    component: $component,
    case_id: $case_id,
    source_revision: $source_revision,
    decision: $decision,
    reason_code: $reason_code,
    preflight_report_json: $preflight_path,
    advisory_only: true,
    executed_command_under_inspection: false
  }' >"$manifest_tmp"
mv "$manifest_tmp" "$manifest_path"

write_event "preflight.completed" "$decision" "$reason_code"

{
  printf '# Swarm Proof Command Preflight\n\n'
  printf -- "- case_id: \`%s\`\n" "$case_id"
  printf -- "- decision: \`%s\`\n" "$decision"
  printf -- "- reason_code: \`%s\`\n" "$reason_code"
  printf -- '- remediation: %s\n' "$remediation"
} >"$report_path"

exit "$exit_code"
