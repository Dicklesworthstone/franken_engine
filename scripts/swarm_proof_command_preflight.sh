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

# Split the direct `env` prefix without evaluating it. This deliberately handles
# only the simple shell quoting used by proof command text: whitespace-separated
# words, single/double quotes, and backslash escapes. It never performs command,
# parameter, glob, or arithmetic expansion.
declare -a simple_shell_words=()
split_simple_shell_words() {
  local input="$1"
  local char=""
  local word=""
  local state="unquoted"
  local escaped="false"
  local word_started="false"
  local unsafe_expansion="false"
  local index

  simple_shell_words=()
  for ((index = 0; index < ${#input}; index += 1)); do
    char="${input:index:1}"
    case "$state" in
      unquoted)
        if [[ "$escaped" == "true" ]]; then
          word+="$char"
          escaped="false"
          word_started="true"
        elif [[ "$char" == "\\" ]]; then
          escaped="true"
          word_started="true"
        elif [[ "$char" == "'" ]]; then
          state="single"
          word_started="true"
        elif [[ "$char" == '"' ]]; then
          state="double"
          word_started="true"
        elif [[ "$char" == '$' || "$char" == '`' || "$char" == ';' ||
          "$char" == '&' || "$char" == '|' || "$char" == '<' ||
          "$char" == '>' || "$char" == '(' || "$char" == ')' ||
          "$char" == '*' || "$char" == '?' || "$char" == '[' ||
          "$char" == ']' || "$char" == '{' || "$char" == '}' ||
          "$char" == '#' || "$char" == '~' ]]; then
          unsafe_expansion="true"
          word+="$char"
          word_started="true"
        elif [[ "$char" =~ [[:space:]] ]]; then
          if [[ "$word_started" == "true" ]]; then
            simple_shell_words+=("$word")
            word=""
            word_started="false"
          fi
        else
          word+="$char"
          word_started="true"
        fi
        ;;
      single)
        if [[ "$char" == "'" ]]; then
          state="unquoted"
        else
          word+="$char"
        fi
        ;;
      double)
        if [[ "$escaped" == "true" ]]; then
          word+="$char"
          escaped="false"
        elif [[ "$char" == "\\" ]]; then
          escaped="true"
        elif [[ "$char" == '"' ]]; then
          state="unquoted"
        elif [[ "$char" == '$' || "$char" == '`' ]]; then
          unsafe_expansion="true"
          word+="$char"
        else
          word+="$char"
        fi
        ;;
    esac
  done

  if [[ "$escaped" == "true" || "$state" != "unquoted" || "$unsafe_expansion" == "true" ]]; then
    return 1
  fi
  if [[ "$word_started" == "true" ]]; then
    simple_shell_words+=("$word")
  fi
}

rustflags_has_effective_linker_policy() {
  local rustflags="$1"
  local -a rustflag_tokens=()
  local index
  local effective_state="unset"

  read -r -a rustflag_tokens <<<"$rustflags"
  for ((index = 0; index < ${#rustflag_tokens[@]}; index += 1)); do
    case "${rustflag_tokens[index]}" in
      -Clinker-features=-lld)
        effective_state="disabled"
        ;;
      -Clinker-features=*)
        effective_state="other"
        ;;
      -C)
        case "${rustflag_tokens[index + 1]:-}" in
          linker-features=-lld)
            effective_state="disabled"
            ;;
          linker-features=*)
            effective_state="other"
            ;;
        esac
        ;;
    esac
  done
  [[ "$effective_state" == "disabled" ]]
}

is_allowed_remote_env() {
  case "$1" in
    CARGO_TARGET_DIR|CARGO_INCREMENTAL|CARGO_BUILD_JOBS|CARGO_PROFILE_DEV_DEBUG|RUSTFLAGS|RUSTUP_TOOLCHAIN)
      return 0
      ;;
    *)
      return 1
      ;;
  esac
}

is_allowed_client_env() {
  case "$1" in
    RCH_VISIBILITY|RCH_PRIORITY|RCH_DAEMON_WAIT_RESPONSE_TIMEOUT_SECS|RCH_REQUIRE_REMOTE|RCH_QUEUE_WHEN_BUSY|RCH_TEST_TIMEOUT_SEC|RCH_BUILD_TIMEOUT_SEC)
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
safe_client_prefix="env -u CARGO_ENCODED_RUSTFLAGS"
if [[ "$evidence_requires_visibility" == "true" ]]; then
  safe_client_prefix="${safe_client_prefix} RCH_VISIBILITY=verbose"
fi
safe_env_prefix="CARGO_TARGET_DIR=${safe_target_dir} CARGO_INCREMENTAL=0 CARGO_BUILD_JOBS=1"

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

client_encoded_rustflags_cleared="false"
remote_encoded_rustflags_cleared="false"
client_env_parse_ok="true"
transport_command="$normalized_command"
client_env_segment=""

if [[ "$normalized_command" == "env -u CARGO_ENCODED_RUSTFLAGS "* ]]; then
  client_encoded_rustflags_cleared="true"
  client_remainder="${normalized_command#env -u CARGO_ENCODED_RUSTFLAGS }"
  if [[ "$client_remainder" == rch\ exec* ]]; then
    transport_command="$client_remainder"
  elif [[ "$client_remainder" == *" rch exec "* ]]; then
    client_env_segment="${client_remainder%% rch exec *}"
    transport_command="rch exec ${client_remainder#* rch exec }"
  else
    client_env_parse_ok="false"
  fi
fi

transport="unknown"
if [[ "$transport_command" =~ ^rch[[:space:]]+exec[[:space:]]+--[[:space:]]+env[[:space:]] ]]; then
  transport="rch_direct_env"
elif [[ "$transport_command" =~ ^rch[[:space:]]+exec[[:space:]]+--([[:space:]]|$) ]]; then
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
  pasteable_command="${safe_client_prefix} rch exec -- env -u CARGO_ENCODED_RUSTFLAGS ${safe_env_prefix} ${cargo_suffix}"
fi

declare -a env_assignments=()
declare -a unsupported_env=()
declare -a client_env_assignments=()
declare -a remote_env_assignments=()
rustflags_present="false"
rustflags_linker_policy_composed="false"
env_prefix_parse_ok="true"
has_visibility="false"
visibility_value=""
if [[ -n "$client_env_segment" ]]; then
  if split_simple_shell_words "$client_env_segment"; then
    for token in "${simple_shell_words[@]}"; do
      if [[ "$token" != *=* ]]; then
        client_env_parse_ok="false"
        continue
      fi
      env_name="${token%%=*}"
      client_env_assignments+=("$env_name")
      env_assignments+=("$env_name")
      if ! is_allowed_client_env "$env_name"; then
        unsupported_env+=("$env_name")
      fi
      if [[ "$env_name" == "RCH_VISIBILITY" ]]; then
        visibility_value="${token#*=}"
        if [[ -n "$visibility_value" ]]; then
          has_visibility="true"
        fi
      fi
    done
  else
    client_env_parse_ok="false"
  fi
fi

has_target_dir="false"
target_dir_value=""
target_dir_correlates_with_bead="false"
if [[ "$transport" == "rch_direct_env" && "$transport_command" == *" cargo "* ]]; then
  env_segment="${transport_command#rch exec -- env }"
  if [[ "$env_segment" == "-u CARGO_ENCODED_RUSTFLAGS "* ]]; then
    remote_encoded_rustflags_cleared="true"
  fi
  if split_simple_shell_words "$env_segment"; then
    cargo_seen="false"
    token_index=0
    if [[ "${simple_shell_words[0]:-}" == "-u" \
      && "${simple_shell_words[1]:-}" == "CARGO_ENCODED_RUSTFLAGS" ]]; then
      remote_encoded_rustflags_cleared="true"
      token_index=2
    fi
    for ((; token_index < ${#simple_shell_words[@]}; token_index += 1)); do
      token="${simple_shell_words[token_index]}"
      if [[ "$token" == "cargo" ]]; then
        cargo_seen="true"
        break
      fi
      if [[ "$token" != *=* ]]; then
        env_prefix_parse_ok="false"
        continue
      fi
      env_name="${token%%=*}"
      env_value="${token#*=}"
      remote_env_assignments+=("$env_name")
      env_assignments+=("$env_name")
      if ! is_allowed_remote_env "$env_name"; then
        unsupported_env+=("$env_name")
      fi
      case "$env_name" in
        CARGO_TARGET_DIR)
          has_target_dir="true"
          target_dir_value="$env_value"
          ;;
        RUSTFLAGS)
          rustflags_present="true"
          rustflags_linker_policy_composed="false"
          if rustflags_has_effective_linker_policy "$env_value"; then
            rustflags_linker_policy_composed="true"
          fi
          ;;
      esac
    done
    if [[ "$cargo_seen" != "true" ]]; then
      env_prefix_parse_ok="false"
    fi
  else
    env_prefix_parse_ok="false"
  fi
fi
if [[ "$client_env_parse_ok" != "true" ]]; then
  env_prefix_parse_ok="false"
fi
if [[ "$has_target_dir" == "true" \
  && "$(safe_token "$target_dir_value")" == *"$safe_bead"* ]]; then
  target_dir_correlates_with_bead="true"
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
  if [[ "$client_encoded_rustflags_cleared" != "true" \
    || "$remote_encoded_rustflags_cleared" != "true" ]]; then
    decision="proof_unsafe"
    reason_code="missing_encoded_rustflags_clear"
    remediation="Clear CARGO_ENCODED_RUSTFLAGS on both the RCH client and worker before scheduling proof: ${pasteable_command}"
  elif [[ "$env_prefix_parse_ok" != "true" ]]; then
    decision="proof_unsafe"
    reason_code="unsupported_env_syntax"
    remediation="Use only allowlisted NAME=value assignments after the required remote env -u CARGO_ENCODED_RUSTFLAGS prefix: ${pasteable_command}"
  elif [[ "${#unsupported_env[@]}" -gt 0 ]]; then
    decision="proof_unsafe"
    reason_code="unsupported_env_leakage"
    remediation="Remove unsupported env assignments ($(join_by_comma "${unsupported_env[@]}")) and use the allowlisted shape: ${pasteable_command}"
  elif [[ "$has_target_dir" != "true" ]]; then
    decision="proof_unsafe"
    reason_code="missing_target_dir_policy"
    remediation="Add an isolated target dir before scheduling proof: ${pasteable_command}"
  elif [[ "$target_dir_correlates_with_bead" != "true" ]]; then
    decision="proof_unsafe"
    reason_code="target_dir_bead_mismatch"
    remediation="Use a target dir correlated with bead ${bead_id}: ${pasteable_command}"
  elif [[ "$rustflags_present" == "true" && "$rustflags_linker_policy_composed" != "true" ]]; then
    decision="proof_unsafe"
    reason_code="uncomposed_rustflags_override"
    remediation="Omit RUSTFLAGS to inherit .cargo/config.toml, or include the exact -Clinker-features=-lld token (the two-token -C linker-features=-lld form is also accepted): ${pasteable_command}"
  elif [[ "$evidence_requires_visibility" == "true" && "$has_visibility" != "true" ]]; then
    decision="proof_unsafe"
    reason_code="missing_rch_visibility"
    remediation="Add RCH_VISIBILITY=verbose for evidence capture before scheduling proof: ${pasteable_command}"
  else
    decision="proof_safe"
    reason_code="direct_rch_cargo_proof"
    pasteable_command="$normalized_command"
    remediation="Command is preflight-safe; preserve both encoded-flag clears, direct rch exec -- env argv, CARGO_TARGET_DIR, and the client/remote env allowlists when scheduling proof."
    exit_code=0
  fi
elif [[ "$heavy_cargo" == "true" ]]; then
  decision="proof_unsafe"
  reason_code="unsupported_heavy_command_shape"
  remediation="Normalize the heavy proof command into direct RCH argv before scheduling: ${pasteable_command}"
fi

env_assignments_json="$(array_to_json "${env_assignments[@]}")"
unsupported_env_json="$(array_to_json "${unsupported_env[@]}")"
client_env_assignments_json="$(array_to_json "${client_env_assignments[@]}")"
remote_env_assignments_json="$(array_to_json "${remote_env_assignments[@]}")"

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
  --arg target_dir_value "$target_dir_value" \
  --arg target_dir_correlates_with_bead "$target_dir_correlates_with_bead" \
  --argjson env_assignments "$env_assignments_json" \
  --argjson unsupported_env "$unsupported_env_json" \
  --argjson client_env_assignments "$client_env_assignments_json" \
  --argjson remote_env_assignments "$remote_env_assignments_json" \
  --arg client_encoded_rustflags_cleared "$client_encoded_rustflags_cleared" \
  --arg remote_encoded_rustflags_cleared "$remote_encoded_rustflags_cleared" \
  --arg evidence_requires_visibility "$evidence_requires_visibility" \
  --arg has_target_dir "$has_target_dir" \
  --arg has_visibility "$has_visibility" \
  --arg rustflags_present "$rustflags_present" \
  --arg rustflags_linker_policy_composed "$rustflags_linker_policy_composed" \
  --arg env_prefix_parse_ok "$env_prefix_parse_ok" \
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
      client_env_assignments: $client_env_assignments,
      remote_env_assignments: $remote_env_assignments,
      client_encoded_rustflags_cleared: ($client_encoded_rustflags_cleared == "true"),
      remote_encoded_rustflags_cleared: ($remote_encoded_rustflags_cleared == "true"),
      has_target_dir: ($has_target_dir == "true"),
      target_dir: (if $target_dir_value == "" then null else $target_dir_value end),
      target_dir_correlates_with_bead: ($target_dir_correlates_with_bead == "true"),
      evidence_requires_visibility: ($evidence_requires_visibility == "true"),
      has_visibility: ($has_visibility == "true"),
      has_rustflags_override: ($rustflags_present == "true"),
      rustflags_linker_policy_composed: ($rustflags_linker_policy_composed == "true"),
      env_prefix_parse_ok: ($env_prefix_parse_ok == "true")
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
