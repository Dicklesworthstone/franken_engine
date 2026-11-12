#!/usr/bin/env bash
set -euo pipefail

root_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$root_dir"

mode="${1:-ci}"
default_toolchain="$(sed -n 's/^channel = "\(.*\)"/\1/p' "${root_dir}/rust-toolchain.toml" 2>/dev/null | head -n 1)"
toolchain="${RUSTUP_TOOLCHAIN:-${default_toolchain:-nightly-2026-09-21}}"
target_dir="${CARGO_TARGET_DIR:-/tmp/rch_target_franken_engine_version_matrix}"
lanes_csv="${VERSION_MATRIX_LANES:-n,n_minus_1,n_plus_1}"
artifact_root="${VERSION_MATRIX_ARTIFACT_ROOT:-artifacts/version_matrix_lane}"
timestamp="$(date -u +"%Y%m%dT%H%M%SZ")"
run_dir="${artifact_root}/${timestamp}"
manifest_path="${run_dir}/run_manifest.json"
events_path="${run_dir}/version_matrix_events.jsonl"
summary_path="${run_dir}/matrix_summary.json"
commands_path="${run_dir}/commands.txt"
classification_path="${run_dir}/failure_classification.json"
governance_ledger_path="${run_dir}/governance_exemption_ledger.jsonl"
follow_up_path="${run_dir}/exemption_follow_up.json"
logs_dir="${run_dir}/logs"

trace_id="trace-version-matrix-${timestamp}"
decision_id="decision-version-matrix-${timestamp}"
policy_id="policy-version-matrix-v1"
component="version_matrix_lane_runner"

mkdir -p "$logs_dir"

IFS=',' read -r -a lanes <<<"$lanes_csv"

run_rch() {
  if command -v rch >/dev/null 2>&1; then
    rch exec -- env "RUSTUP_TOOLCHAIN=${toolchain}" "CARGO_TARGET_DIR=${target_dir}" "$@"
  elif [[ "${GITHUB_ACTIONS:-false}" == "true" ]]; then
    env "RUSTUP_TOOLCHAIN=${toolchain}" "CARGO_TARGET_DIR=${target_dir}" "$@"
  else
    echo "rch is required for version-matrix lane heavy commands" >&2
    return 2
  fi
}

json_escape() {
  local input="$1"
  input="${input//\\/\\\\}"
  input="${input//\"/\\\"}"
  input="${input//$'\n'/\\n}"
  printf '%s' "$input"
}

trim() {
  local input="$1"
  input="${input#"${input%%[![:space:]]*}"}"
  input="${input%"${input##*[![:space:]]}"}"
  printf '%s' "$input"
}

declare -a commands_run=()
declare -a command_logs=()
declare -a changed_files=()
declare -a gate_reasons=()
failed_command=""
failed_log_path=""
final_outcome="pass"
classification_pre_existing=0
classification_new=0
matched_known_marker=""
conformance_suite_manifest_path=""
conformance_suite_events_path=""

gate_required=false
gate_reason_summary="not-evaluated"
run_conformance_suite_here=false

exemption_present=false
exemption_valid=false
exemption_signature_verified=false
exemption_validation_error=""
exemption_file_path="${SHARED_BOUNDARY_EXEMPTION_FILE:-}"
exemption_id=""
exemption_scope=""
exemption_approved_by=""
exemption_approved_at_utc=""
exemption_expires_at_utc=""
exemption_risk_acknowledgement=""
exemption_justification=""
exemption_signature=""
exemption_follow_up_bead=""

load_changed_files() {
  local base_sha="${SHARED_BOUNDARY_BASE_SHA:-}"
  local head_sha="${SHARED_BOUNDARY_HEAD_SHA:-}"
  local changed_raw=""

  if [[ -n "${SHARED_BOUNDARY_CHANGED_FILES:-}" ]]; then
    changed_raw="${SHARED_BOUNDARY_CHANGED_FILES}"
  elif [[ -n "$base_sha" && -n "$head_sha" ]] \
    && git cat-file -e "${base_sha}^{commit}" >/dev/null 2>&1 \
    && git cat-file -e "${head_sha}^{commit}" >/dev/null 2>&1; then
    changed_raw="$(git diff --name-only "$base_sha" "$head_sha")"
  elif git rev-parse --verify HEAD~1 >/dev/null 2>&1; then
    changed_raw="$(git diff --name-only HEAD~1 HEAD)"
  else
    changed_raw="$(git ls-files)"
  fi

  while IFS= read -r line; do
    line="$(trim "$line")"
    [[ -z "$line" ]] && continue
    changed_files+=("$line")
  done <<<"$changed_raw"
}

is_shared_boundary_path() {
  local path="$1"
  case "$path" in
    .github/workflows/version_matrix_conformance.yml|\
    scripts/run_version_matrix_lane.sh|\
    scripts/run_conformance_suite.sh|\
    crates/franken-engine/src/conformance_catalog.rs|\
    crates/franken-engine/src/conformance_vector_gen.rs|\
    crates/franken-engine/src/cross_repo_contract.rs|\
    crates/franken-engine/src/conformance_harness.rs|\
    crates/franken-engine/src/version_matrix_lane.rs|\
    crates/franken-engine/src/module_compatibility_matrix.rs|\
    crates/franken-engine/src/migration_compatibility.rs|\
    crates/franken-engine/tests/conformance_*|\
    crates/franken-engine/tests/version_matrix_lane.rs|\
    crates/franken-engine/tests/module_compatibility_matrix.rs|\
    crates/franken-engine/tests/sqlmodel_rust_boundary.rs)
      return 0
      ;;
    # Conservative transitive trigger: any Rust source/test change in engine or extension-host.
    crates/franken-engine/src/*.rs|crates/franken-engine/tests/*.rs|crates/franken-extension-host/src/*.rs)
      return 0
      ;;
    *)
      return 1
      ;;
  esac
}

has_shared_schema_change() {
  local path="$1"
  local base_sha="${SHARED_BOUNDARY_BASE_SHA:-}"
  local head_sha="${SHARED_BOUNDARY_HEAD_SHA:-}"
  local diff_text

  if [[ -z "$base_sha" || -z "$head_sha" ]] \
    || ! git cat-file -e "${base_sha}^{commit}" >/dev/null 2>&1 \
    || ! git cat-file -e "${head_sha}^{commit}" >/dev/null 2>&1; then
    return 1
  fi

  diff_text="$(git diff --unified=0 "$base_sha" "$head_sha" -- "$path" || true)"
  if [[ -z "$diff_text" ]]; then
    return 1
  fi

  if grep -Eq '^[+-].*(schema_version|surface_id|covered_fields|required_fields|trace_id|decision_id|policy_id|component|event|outcome|error_code|serde\(|Serialize|Deserialize)' <<<"$diff_text"; then
    return 0
  fi

  return 1
}

detect_gate_requirement() {
  local path
  local matched=false
  local schema_matched=false

  if [[ "${SHARED_BOUNDARY_FORCE_GATE:-0}" == "1" ]]; then
    gate_required=true
    gate_reasons+=("forced via SHARED_BOUNDARY_FORCE_GATE=1")
  fi

  load_changed_files

  for path in "${changed_files[@]}"; do
    if is_shared_boundary_path "$path"; then
      matched=true
      gate_reasons+=("path trigger: $path")
    elif has_shared_schema_change "$path"; then
      schema_matched=true
      gate_reasons+=("schema-diff trigger: $path")
    fi
  done

  if [[ "$matched" == true || "$schema_matched" == true ]]; then
    gate_required=true
  fi

  if [[ "${#changed_files[@]}" -eq 0 ]]; then
    # Fail-safe for unknown change graph: run gate to avoid false negatives.
    gate_required=true
    gate_reasons+=("no changed files detected; fail-safe trigger")
  fi

  if [[ "$gate_required" == true ]]; then
    gate_reason_summary="required"
  else
    gate_reason_summary="not-required"
  fi
}

lane_contains() {
  local needle="$1"
  local lane
  for lane in "${lanes[@]}"; do
    if [[ "$lane" == "$needle" ]]; then
      return 0
    fi
  done
  return 1
}

parse_exemption_file() {
  local path="$1"
  local line raw_key raw_value key value

  while IFS= read -r line || [[ -n "$line" ]]; do
    line="$(trim "$line")"
    [[ -z "$line" ]] && continue
    [[ "${line:0:1}" == "#" ]] && continue
    if [[ "$line" != *"="* ]]; then
      continue
    fi
    raw_key="${line%%=*}"
    raw_value="${line#*=}"
    key="$(trim "$raw_key")"
    value="$(trim "$raw_value")"
    if [[ "$value" == \"*\" && "$value" == *\" ]]; then
      value="${value:1:${#value}-2}"
    elif [[ "$value" == \'*\' && "$value" == *\' ]]; then
      value="${value:1:${#value}-2}"
    fi

    case "$key" in
      exemption_id) exemption_id="$value" ;;
      scope) exemption_scope="$value" ;;
      approved_by) exemption_approved_by="$value" ;;
      approved_at_utc) exemption_approved_at_utc="$value" ;;
      expires_at_utc) exemption_expires_at_utc="$value" ;;
      risk_acknowledgement) exemption_risk_acknowledgement="$value" ;;
      justification) exemption_justification="$value" ;;
      signature) exemption_signature="$value" ;;
      follow_up_bead) exemption_follow_up_bead="$value" ;;
      *) ;;
    esac
  done <"$path"
}

validate_exemption() {
  local now_epoch expiry_epoch approved_epoch expected_signature payload key

  exemption_validation_error=""
  exemption_valid=false
  exemption_signature_verified=false

  if [[ -z "$exemption_file_path" || ! -f "$exemption_file_path" ]]; then
    exemption_validation_error="no exemption file provided"
    return 1
  fi
  exemption_present=true

  parse_exemption_file "$exemption_file_path"

  if [[ -z "$exemption_id" || -z "$exemption_scope" || -z "$exemption_approved_by" || -z "$exemption_approved_at_utc" || -z "$exemption_expires_at_utc" || -z "$exemption_risk_acknowledgement" || -z "$exemption_justification" || -z "$exemption_signature" ]]; then
    exemption_validation_error="missing required exemption fields"
    return 1
  fi

  if [[ "$exemption_scope" != "shared-boundary-conformance" && "$exemption_scope" != "all" ]]; then
    exemption_validation_error="invalid exemption scope: $exemption_scope"
    return 1
  fi

  approved_epoch="$(date -u -d "$exemption_approved_at_utc" +%s 2>/dev/null || true)"
  if [[ -z "$approved_epoch" ]]; then
    exemption_validation_error="invalid approved_at_utc timestamp: $exemption_approved_at_utc"
    return 1
  fi

  expiry_epoch="$(date -u -d "$exemption_expires_at_utc" +%s 2>/dev/null || true)"
  if [[ -z "$expiry_epoch" ]]; then
    exemption_validation_error="invalid expires_at_utc timestamp: $exemption_expires_at_utc"
    return 1
  fi
  now_epoch="$(date -u +%s)"
  if (( expiry_epoch <= now_epoch )); then
    exemption_validation_error="exemption has expired at $exemption_expires_at_utc"
    return 1
  fi

  key="${SHARED_BOUNDARY_GOVERNANCE_KEY:-}"
  payload="${exemption_id}|${exemption_scope}|${exemption_approved_by}|${exemption_approved_at_utc}|${exemption_expires_at_utc}|${exemption_risk_acknowledgement}|${exemption_justification}"
  if [[ -n "$key" ]]; then
    if ! command -v openssl >/dev/null 2>&1; then
      exemption_validation_error="openssl is required to verify signed exemption"
      return 1
    fi
    expected_signature="$(printf '%s' "$payload" | openssl dgst -sha256 -hmac "$key" | sed -E 's/^.*= //')"
    if [[ "$expected_signature" != "$exemption_signature" ]]; then
      exemption_validation_error="signature verification failed"
      return 1
    fi
    exemption_signature_verified=true
  elif [[ "${GITHUB_ACTIONS:-}" == "true" ]]; then
    exemption_validation_error="SHARED_BOUNDARY_GOVERNANCE_KEY must be set in CI for signed exemptions"
    return 1
  fi

  exemption_valid=true
  return 0
}

load_known_issue_markers() {
  local waivers_path="${CONFORMANCE_WAIVERS_PATH:-crates/franken-engine/tests/conformance_waivers.toml}"
  local line marker
  if [[ -f "$waivers_path" ]]; then
    while IFS= read -r line; do
      marker="$(sed -E 's/^[^"]*"([^"]+)".*$/\1/' <<<"$line")"
      if [[ -n "$marker" && "$marker" != "$line" ]]; then
        echo "$marker"
      fi
    done < <(grep -E '^(asset_id|tracking_bead)\s*=' "$waivers_path" || true)
  fi
}

classify_failure_origin() {
  local marker
  classification_pre_existing=0
  classification_new=0
  matched_known_marker=""

  if [[ -z "$failed_log_path" || ! -f "$failed_log_path" ]]; then
    return 0
  fi

  while IFS= read -r marker; do
    marker="$(trim "$marker")"
    [[ -z "$marker" ]] && continue
    if grep -Fq "$marker" "$failed_log_path"; then
      classification_pre_existing=1
      classification_new=0
      matched_known_marker="$marker"
      return 0
    fi
  done < <(load_known_issue_markers)

  classification_pre_existing=0
  classification_new=1
}

run_step() {
  local command_text="$1"
  shift
  local step_index="${#commands_run[@]}"
  local log_path="${logs_dir}/step_$(printf '%02d' "$step_index").log"
  commands_run+=("$command_text")
  command_logs+=("$log_path")
  echo "==> $command_text"
  if "$@" > >(tee "$log_path") 2>&1; then
    return 0
  fi
  failed_command="$command_text"
  failed_log_path="$log_path"
  return 1
}

run_matrix_tests() {
  local lane
  for lane in "${lanes[@]}"; do
    run_step "VERSION_MATRIX_LANE=${lane} cargo test -p frankenengine-engine --test conformance_assets" \
      run_rch env "VERSION_MATRIX_LANE=${lane}" cargo test -p frankenengine-engine --test conformance_assets
    run_step "VERSION_MATRIX_LANE=${lane} cargo test -p frankenengine-engine --test conformance_min_repro" \
      run_rch env "VERSION_MATRIX_LANE=${lane}" cargo test -p frankenengine-engine --test conformance_min_repro
  done
}

run_check() {
  run_step "cargo check -p frankenengine-engine --test version_matrix_lane" \
    run_rch cargo check -p frankenengine-engine --test version_matrix_lane
}

run_test() {
  run_step "cargo test -p frankenengine-engine --test version_matrix_lane" \
    run_rch cargo test -p frankenengine-engine --test version_matrix_lane
  run_matrix_tests
}

run_mode() {
  local conformance_artifact_root

  if [[ "$gate_required" != true ]]; then
    final_outcome="skipped"
    return 0
  fi

  case "$mode" in
    check)
      run_check
      ;;
    test)
      run_test
      ;;
    ci)
      run_check
      run_test
      ;;
    *)
      echo "usage: $0 [check|test|ci]" >&2
      return 2
      ;;
  esac

  if [[ "$run_conformance_suite_here" == true ]]; then
    conformance_artifact_root="${run_dir}/conformance_suite"
    run_step "CONFORMANCE_ARTIFACT_ROOT=${conformance_artifact_root} ./scripts/run_conformance_suite.sh ${mode}" \
      env CONFORMANCE_ARTIFACT_ROOT="$conformance_artifact_root" ./scripts/run_conformance_suite.sh "$mode"
    conformance_suite_manifest_path="$(find "$conformance_artifact_root" -name run_manifest.json | sort | tail -n 1)"
    conformance_suite_events_path="$(find "$conformance_artifact_root" -name conformance_suite_events.jsonl | sort | tail -n 1)"
  fi

  final_outcome="pass"
  return 0
}

write_lane_summary() {
  local lane idx comma lane_outcome
  {
    echo "{"
    echo '  "schema_version": "franken-engine.version-matrix-lane.summary.v2",'
    echo "  \"generated_at_utc\": \"$(json_escape "$timestamp")\","
    echo "  \"gate_required\": ${gate_required},"
    echo "  \"outcome\": \"$(json_escape "$final_outcome")\","
    echo '  "lanes": ['
    for idx in "${!lanes[@]}"; do
      lane="${lanes[$idx]}"
      comma=","
      lane_outcome="pass"
      if [[ "$idx" == "$(( ${#lanes[@]} - 1 ))" ]]; then
        comma=""
      fi
      if [[ "$final_outcome" == "fail" || "$final_outcome" == "exempted" ]]; then
        lane_outcome="$final_outcome"
      fi
      if [[ "$final_outcome" == "skipped" ]]; then
        lane_outcome="skipped"
      fi
      echo "    {\"lane\":\"$(json_escape "$lane")\",\"outcome\":\"$(json_escape "$lane_outcome")\"}${comma}"
    done
    echo '  ]'
    echo "}"
  } >"$summary_path"
}

write_classification_artifact() {
  local idx comma line
  local -a failure_id_lines=()
  local -a failing_test_lines=()

  while IFS= read -r line; do
    line="$(trim "$line")"
    [[ -z "$line" ]] && continue
    failure_id_lines+=("$line")
  done < <(grep -oE 'cf-[0-9a-f]{16}' "$failed_log_path" 2>/dev/null | sort -u || true)

  while IFS= read -r line; do
    line="$(trim "$line")"
    [[ -z "$line" ]] && continue
    failing_test_lines+=("$line")
  done < <(sed -n 's/^---- \(.*\) stdout ----$/\1/p' "$failed_log_path" 2>/dev/null | sort -u || true)

  {
    echo "{"
    echo '  "schema_version": "franken-engine.shared-boundary-failure-classification.v1",'
    echo "  \"pre_existing_failures\": ${classification_pre_existing},"
    echo "  \"new_regressions\": ${classification_new},"
    echo "  \"matched_known_marker\": \"$(json_escape "$matched_known_marker")\","
    echo "  \"failed_command\": \"$(json_escape "$failed_command")\","
    echo "  \"failed_log\": \"$(json_escape "$failed_log_path")\","
    echo '  "failure_ids": ['
    for idx in "${!failure_id_lines[@]}"; do
      comma=","
      if [[ "$idx" == "$(( ${#failure_id_lines[@]} - 1 ))" ]]; then
        comma=""
      fi
      echo "    \"$(json_escape "${failure_id_lines[$idx]}")\"${comma}"
    done
    echo '  ],'
    echo '  "failing_tests": ['
    for idx in "${!failing_test_lines[@]}"; do
      comma=","
      if [[ "$idx" == "$(( ${#failing_test_lines[@]} - 1 ))" ]]; then
        comma=""
      fi
      echo "    \"$(json_escape "${failing_test_lines[$idx]}")\"${comma}"
    done
    echo '  ]'
    echo "}"
  } >"$classification_path"
}

write_exemption_follow_up() {
  {
    echo "{"
    echo '  "schema_version": "franken-engine.shared-boundary-exemption-follow-up.v1",'
    echo "  \"follow_up_id\": \"$(json_escape "follow-up-${exemption_id}-${timestamp}")\","
    echo "  \"exemption_id\": \"$(json_escape "$exemption_id")\","
    echo "  \"tracking_bead\": \"$(json_escape "$exemption_follow_up_bead")\","
    echo "  \"due_at_utc\": \"$(json_escape "$exemption_expires_at_utc")\","
    echo '  "status": "open",'
    echo "  \"failed_command\": \"$(json_escape "$failed_command")\","
    echo "  \"classification_path\": \"$(json_escape "$classification_path")\""
    echo "}"
  } >"$follow_up_path"
}

write_governance_ledger_event() {
  cat >"$governance_ledger_path" <<JSONL
{"trace_id":"${trace_id}","decision_id":"${decision_id}","policy_id":"${policy_id}","component":"${component}","event":"shared_boundary_exemption_applied","outcome":"pass","error_code":null,"exemption_id":"${exemption_id}","scope":"${exemption_scope}","approved_by":"${exemption_approved_by}","expires_at_utc":"${exemption_expires_at_utc}","signature_verified":${exemption_signature_verified},"failed_command":"${failed_command}"}
JSONL
}

write_manifest() {
  local exit_code="${1:-0}"
  local error_code idx comma changed_comma reason_comma
  local failed_log_json="null"
  local classification_json="null"
  local conformance_manifest_json="null"
  local conformance_events_json="null"
  local governance_json="null"
  local follow_up_json="null"

  if [[ "$final_outcome" == "pass" ]]; then
    error_code="null"
  elif [[ "$final_outcome" == "skipped" ]]; then
    error_code="null"
  elif [[ "$final_outcome" == "exempted" ]]; then
    error_code='"FE-SHARED-BOUNDARY-EXEMPTED"'
  else
    error_code='"FE-SHARED-BOUNDARY-GATE-0001"'
  fi

  printf '%s\n' "${commands_run[@]}" >"$commands_path"

  if [[ -n "$failed_log_path" ]]; then
    failed_log_json="\"$(json_escape "$failed_log_path")\""
  fi
  if [[ -f "$classification_path" ]]; then
    classification_json="\"$(json_escape "$classification_path")\""
  fi
  if [[ -n "$conformance_suite_manifest_path" ]]; then
    conformance_manifest_json="\"$(json_escape "$conformance_suite_manifest_path")\""
  fi
  if [[ -n "$conformance_suite_events_path" ]]; then
    conformance_events_json="\"$(json_escape "$conformance_suite_events_path")\""
  fi
  if [[ -f "$governance_ledger_path" ]]; then
    governance_json="\"$(json_escape "$governance_ledger_path")\""
  fi
  if [[ -f "$follow_up_path" ]]; then
    follow_up_json="\"$(json_escape "$follow_up_path")\""
  fi

  cat >"$events_path" <<JSONL
{"trace_id":"${trace_id}","decision_id":"${decision_id}","policy_id":"${policy_id}","component":"${component}","event":"matrix_run_completed","outcome":"${final_outcome}","error_code":${error_code},"mode":"${mode}","gate_required":${gate_required}}
JSONL

  {
    echo "{"
    echo '  "schema_version": "franken-engine.version-matrix-lane.run-manifest.v3",'
    echo '  "bead_id": "bd-1999",'
    echo "  \"timestamp_utc\": \"$(json_escape "$timestamp")\","
    echo "  \"mode\": \"$(json_escape "$mode")\","
    echo "  \"toolchain\": \"$(json_escape "$toolchain")\","
    echo "  \"cargo_target_dir\": \"$(json_escape "$target_dir")\","
    echo "  \"trace_id\": \"$(json_escape "$trace_id")\","
    echo "  \"decision_id\": \"$(json_escape "$decision_id")\","
    echo "  \"policy_id\": \"$(json_escape "$policy_id")\","
    echo "  \"outcome\": \"$(json_escape "$final_outcome")\","
    echo "  \"gate_required\": ${gate_required},"
    echo "  \"gate_reason_summary\": \"$(json_escape "$gate_reason_summary")\","
    echo "  \"failed_command\": \"$(json_escape "$failed_command")\","
    echo "  \"failed_log\": ${failed_log_json},"
    echo "  \"classification_artifact\": ${classification_json},"
    echo "  \"conformance_suite_manifest\": ${conformance_manifest_json},"
    echo "  \"conformance_suite_events\": ${conformance_events_json},"
    echo "  \"governance_exemption_ledger\": ${governance_json},"
    echo "  \"exemption_follow_up\": ${follow_up_json},"
    echo '  "lanes": ['
    for idx in "${!lanes[@]}"; do
      comma=","
      if [[ "$idx" == "$(( ${#lanes[@]} - 1 ))" ]]; then
        comma=""
      fi
      echo "    \"$(json_escape "${lanes[$idx]}")\"${comma}"
    done
    echo '  ],'
    echo '  "changed_files": ['
    for idx in "${!changed_files[@]}"; do
      changed_comma=","
      if [[ "$idx" == "$(( ${#changed_files[@]} - 1 ))" ]]; then
        changed_comma=""
      fi
      echo "    \"$(json_escape "${changed_files[$idx]}")\"${changed_comma}"
    done
    echo '  ],'
    echo '  "gate_reasons": ['
    for idx in "${!gate_reasons[@]}"; do
      reason_comma=","
      if [[ "$idx" == "$(( ${#gate_reasons[@]} - 1 ))" ]]; then
        reason_comma=""
      fi
      echo "    \"$(json_escape "${gate_reasons[$idx]}")\"${reason_comma}"
    done
    echo '  ],'
    echo '  "commands": ['
    for idx in "${!commands_run[@]}"; do
      comma=","
      if [[ "$idx" == "$(( ${#commands_run[@]} - 1 ))" ]]; then
        comma=""
      fi
      echo "    \"$(json_escape "${commands_run[$idx]}")\"${comma}"
    done
    echo '  ],'
    echo '  "command_logs": ['
    for idx in "${!command_logs[@]}"; do
      comma=","
      if [[ "$idx" == "$(( ${#command_logs[@]} - 1 ))" ]]; then
        comma=""
      fi
      echo "    \"$(json_escape "${command_logs[$idx]}")\"${comma}"
    done
    echo '  ],'
    echo '  "evidence_pointers": ['
    echo "    \"$(json_escape "$events_path")\","
    echo "    \"$(json_escape "$summary_path")\""
    echo '  ],'
    echo '  "replay_pointers": ['
    echo '    "franken-conformance replay minimized_repros/<failure_id>.json",'
    echo '    "franken-conformance replay minimized_repros/<failure_id>.json --verify"'
    echo '  ],'
    echo '  "operator_verification": ['
    echo "    \"cat $(json_escape "$manifest_path")\","
    echo "    \"cat $(json_escape "$summary_path")\","
    echo "    \"cat $(json_escape "$events_path")\","
    echo "    \"cat $(json_escape "$commands_path")\","
    echo "    \"${0} ci\""
    echo '  ]'
    echo "}"
  } >"$manifest_path"
}

detect_gate_requirement

primary_lane="${CONFORMANCE_SUITE_PRIMARY_LANE:-n}"
if [[ "${RUN_CONFORMANCE_SUITE_WITH_MATRIX_GATE:-1}" == "1" ]] && lane_contains "$primary_lane"; then
  run_conformance_suite_here=true
fi

set +e
run_mode
run_exit_code=$?
set -e

if [[ "$run_exit_code" -ne 0 && "$gate_required" == true ]]; then
  final_outcome="fail"
  classify_failure_origin
  write_classification_artifact
  if validate_exemption; then
    final_outcome="exempted"
    write_governance_ledger_event
    write_exemption_follow_up
    run_exit_code=0
  fi
fi

write_lane_summary
write_manifest "$run_exit_code"

echo "version matrix run manifest: ${manifest_path}"
echo "version matrix events: ${events_path}"
echo "version matrix summary: ${summary_path}"

if [[ "$final_outcome" == "fail" && -n "$exemption_validation_error" ]]; then
  echo "shared-boundary exemption rejected: ${exemption_validation_error}" >&2
fi

exit "$run_exit_code"
