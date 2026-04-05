#!/usr/bin/env bash
set -euo pipefail

root_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$root_dir"

mode="${1:-ci}"
toolchain="${RUSTUP_TOOLCHAIN:-nightly}"
rch_timeout_seconds="${RCH_EXEC_TIMEOUT_SECONDS:-900}"
artifact_root="${PARSER_ORACLE_ARTIFACT_ROOT:-artifacts/parser_oracle}"
partition="${PARSER_ORACLE_PARTITION:-smoke}"
gate_mode="${PARSER_ORACLE_GATE_MODE:-report_only}"
seed="${PARSER_ORACLE_SEED:-1}"
fixture_catalog="${PARSER_ORACLE_FIXTURE_CATALOG:-crates/franken-engine/tests/fixtures/parser_phase0_semantic_fixtures.json}"
report_schema_version="${PARSER_ORACLE_REPORT_SCHEMA_VERSION:-franken-engine.parser-oracle.report.v1}"
taxonomy_version="${PARSER_ORACLE_TAXONOMY_VERSION:-franken-engine.parser-oracle.taxonomy.v1}"
remediation_map_version="${PARSER_ORACLE_REMEDIATION_MAP_VERSION:-franken-engine.parser-oracle.remediation-map.v1}"
missing_artifact_contract_json="${root_dir}/docs/parser_oracle_missing_artifact_contract_v1.json"

timestamp="$(date -u +%Y%m%dT%H%M%SZ)"
if [[ -n "${CARGO_TARGET_DIR:-}" ]]; then
  target_dir="${CARGO_TARGET_DIR}"
else
  target_dir="/tmp/rch_target_franken_engine_parser_oracle_gate_${timestamp}"
fi
run_dir="${artifact_root}/${timestamp}"
manifest_path="${run_dir}/manifest.json"
events_path="${run_dir}/events.jsonl"
commands_path="${run_dir}/commands.txt"
command_logs_dir="${run_dir}/command_logs"
baseline_path="${run_dir}/baseline.json"
relation_report_path="${run_dir}/relation_report.json"
relation_events_path="${run_dir}/relation_events.jsonl"
evidence_path="${run_dir}/metamorphic_evidence.jsonl"
failures_dir="${run_dir}/minimized_failures"
golden_checksums_path="${run_dir}/golden_checksums.txt"
proof_note_path="${run_dir}/proof_note.md"
drift_digest_path="${run_dir}/drift_digest.md"
env_path="${run_dir}/env.json"
repro_lock_path="${run_dir}/repro.lock"
missing_artifact_receipt_path="${run_dir}/parser_oracle_missing_artifact_receipt.json"

trace_id="trace-parser-oracle-${timestamp}"
decision_id="decision-parser-oracle-${timestamp}"
policy_id="policy-parser-oracle-v1"

prepare_run_context() {
  mkdir -p "$run_dir" "$failures_dir" "$command_logs_dir"

  local bootstrap_script
  bootstrap_script="${root_dir}/scripts/e2e/parser_oracle_env_bootstrap.sh"
  if [[ -f "$bootstrap_script" ]]; then
    # shellcheck source=/dev/null
    source "$bootstrap_script"
    if declare -F parser_oracle_apply_deterministic_env >/dev/null 2>&1; then
      parser_oracle_apply_deterministic_env
    fi
  fi
}

ensure_required_tools() {
  if ! command -v jq >/dev/null 2>&1; then
    echo "jq is required for parser oracle gate artifact validation" >&2
    exit 2
  fi
  if ! command -v rch >/dev/null 2>&1; then
    echo "rch is required for parser oracle gate heavy commands" >&2
    exit 2
  fi
}

run_rch() {
  timeout "${rch_timeout_seconds}" \
    rch exec -- env "RUSTUP_TOOLCHAIN=${toolchain}" "CARGO_TARGET_DIR=${target_dir}" "$@"
}

rch_strip_ansi() {
  perl -pe 's/\e\[[0-9;?]*[ -\/]*[@-~]//g' "$1"
}

rch_remote_exit_code() {
  local log_path="$1"
  local remote_exit_line remote_exit_code

  remote_exit_line="$(
    rch_strip_ansi "$log_path" | rg -o 'Remote command finished: exit=[0-9]+' | tail -n 1 || true
  )"
  if [[ -z "$remote_exit_line" ]]; then
    return 1
  fi

  remote_exit_code="${remote_exit_line##*=}"
  if [[ -z "$remote_exit_code" ]]; then
    return 1
  fi

  printf '%s\n' "$remote_exit_code"
}

rch_reject_local_fallback() {
  local log_path="$1"
  if rch_strip_ansi "$log_path" | grep -Eiq 'Remote execution failed: Project sync failed|running locally|Remote toolchain failure, falling back to local|falling back to local|fallback to local|local fallback|\[RCH\] local \('; then
    echo "rch reported local fallback; refusing local execution for heavy command" >&2
    return 1
  fi
}

relation_report_has_contract() {
  local actual_schema actual_taxonomy

  [[ -f "$relation_report_path" ]] || return 1
  actual_schema="$(jq -r '.schema_version // empty' "$relation_report_path" 2>/dev/null || true)"
  actual_taxonomy="$(jq -r '.taxonomy_version // empty' "$relation_report_path" 2>/dev/null || true)"

  [[ "$actual_schema" == "$report_schema_version" && "$actual_taxonomy" == "$taxonomy_version" ]]
}

recover_relation_report_from_command_log() {
  local command_log_path="$1"
  local stripped_log_path candidate_report_path

  [[ -f "$command_log_path" ]] || return 1

  stripped_log_path="$(mktemp)"
  candidate_report_path="$(mktemp)"
  rch_strip_ansi "$command_log_path" >"$stripped_log_path"

  awk '
    BEGIN { capture = 0; depth = 0 }
    {
      line = $0
      if (!capture) {
        if (line ~ /^[[:space:]]*\{[[:space:]]*$/) {
          capture = 1
        } else {
          next
        }
      }

      print line
      open_count = gsub(/\{/, "{", line)
      close_count = gsub(/\}/, "}", line)
      depth += open_count - close_count

      if (capture && depth == 0) {
        exit
      }
    }
  ' "$stripped_log_path" >"$candidate_report_path"

  rm -f "$stripped_log_path"

  if ! jq -e '
    (.schema_version // empty) != "" and
    (.taxonomy_version // empty) != "" and
    (.summary | type == "object") and
    (.decision | type == "object")
  ' "$candidate_report_path" >/dev/null 2>&1; then
    rm -f "$candidate_report_path"
    return 1
  fi

  mkdir -p "$(dirname "$relation_report_path")"
  mv "$candidate_report_path" "$relation_report_path"
}

pairs_for_partition() {
  case "$1" in
    smoke) echo "64" ;;
    full) echo "256" ;;
    nightly) echo "1024" ;;
    *)
      echo "unsupported PARSER_ORACLE_PARTITION: $1" >&2
      return 2
      ;;
  esac
}

remediation_for_class() {
  case "$1" in
    equivalent) echo "none" ;;
    diagnostics_drift)
      echo "inspect normalized diagnostics envelope and taxonomy mapping"
      ;;
    semantic_drift)
      echo "replay fixture and compare canonical AST/hash materialization"
      ;;
    harness_nondeterminism)
      echo "rerun with fixed seed/order and verify deterministic environment bootstrap"
      ;;
    artifact_integrity_failure)
      echo "verify expected fixture hash and artifact checksum provenance"
      ;;
    *) echo "triage parser-oracle drift and classify before promotion" ;;
  esac
}

owner_hint_for_family() {
  case "$1" in
    statement.* | expression.* | declaration.*) echo "parser-core" ;;
    module.* | import.* | export.*) echo "module-system" ;;
    diagnostics.* | error.*) echo "diagnostics" ;;
    *) echo "parser-frontier" ;;
  esac
}

artifact_role_for_path() {
  case "$1" in
    baseline.json) echo "baseline" ;;
    relation_report.json) echo "relation_report" ;;
    relation_events.jsonl) echo "relation_events" ;;
    metamorphic_evidence.jsonl) echo "metamorphic_evidence" ;;
    drift_digest.md) echo "drift_digest" ;;
    parser_oracle_missing_artifact_receipt.json) echo "missing_artifact_receipt" ;;
    *)
      echo "unknown_artifact_role_for_parser_oracle_missing_artifact: $1" >&2
      return 1
      ;;
  esac
}

missing_artifact_reason_field() {
  local reason_id="$1"
  local field="$2"

  jq -r \
    --arg reason_id "$reason_id" \
    --arg field "$field" \
    '
      .artifact_contract.reason_matrix[]
      | select(.reason_id == $reason_id)
      | .[$field]
    ' \
    "$missing_artifact_contract_json"
}

emit_missing_artifact_receipt() {
  local reason_id="$1"
  shift

  if [[ "$#" -eq 0 ]]; then
    rm -f "$missing_artifact_receipt_path"
    return 0
  fi

  local stage reason_code consumer_action first_artifact first_role
  local missing_artifacts_json="[]"

  stage="$(missing_artifact_reason_field "$reason_id" "stage")"
  reason_code="$(missing_artifact_reason_field "$reason_id" "code")"
  consumer_action="$(missing_artifact_reason_field "$reason_id" "consumer_action")"

  if [[ -z "$stage" || -z "$reason_code" || -z "$consumer_action" ]]; then
    echo "parser oracle missing-artifact contract does not define reason_id=${reason_id}" >&2
    return 1
  fi

  first_artifact="$1"
  first_role="$(artifact_role_for_path "$first_artifact")"

  while [[ "$#" -gt 0 ]]; do
    local artifact_path="$1"
    local artifact_role
    artifact_role="$(artifact_role_for_path "$artifact_path")"
    missing_artifacts_json="$(
      jq -c \
        --arg artifact_path "$artifact_path" \
        --arg artifact_role "$artifact_role" \
        '. + [{artifact_path: $artifact_path, artifact_role: $artifact_role}]' \
        <<<"$missing_artifacts_json"
    )"
    shift
  done

  jq -n \
    --arg schema_version "franken-engine.parser-oracle-missing-artifact-receipt.v1" \
    --arg contract_schema_version "franken-engine.parser-oracle-missing-artifact-contract.v1" \
    --arg trace_id "$trace_id" \
    --arg decision_id "$decision_id" \
    --arg policy_id "$policy_id" \
    --arg component "parser_oracle_gate" \
    --arg artifact_path "$first_artifact" \
    --arg artifact_role "$first_role" \
    --arg stage "$stage" \
    --arg reason_code "$reason_code" \
    --arg reason_id "$reason_id" \
    --arg consumer_action "$consumer_action" \
    --arg generated_at_utc "$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
    --argjson placeholder_rejected true \
    --argjson missing_artifacts "$missing_artifacts_json" \
    '{
      schema_version: $schema_version,
      contract_schema_version: $contract_schema_version,
      trace_id: $trace_id,
      decision_id: $decision_id,
      policy_id: $policy_id,
      component: $component,
      artifact_path: $artifact_path,
      artifact_role: $artifact_role,
      stage: $stage,
      reason_code: $reason_code,
      reason_id: $reason_id,
      consumer_action: $consumer_action,
      generated_at_utc: $generated_at_utc,
      placeholder_rejected: $placeholder_rejected,
      missing_artifacts: $missing_artifacts
    }' >"$missing_artifact_receipt_path"
}

select_missing_artifact_reason_id() {
  local exit_code="${1:-0}"

  if [[ -n "${PARSER_ORACLE_MISSING_ARTIFACT_REASON_OVERRIDE:-}" ]]; then
    printf '%s\n' "$PARSER_ORACLE_MISSING_ARTIFACT_REASON_OVERRIDE"
    return 0
  fi

  case "$mode" in
    check|test)
      printf '%s\n' "not_run_by_design"
      ;;
    *)
      if [[ "$exit_code" -ne 0 ]]; then
        if [[ -f "$relation_report_path" ]]; then
          printf '%s\n' "missing_unexpected_absence"
        else
          printf '%s\n' "failed_before_artifact_creation"
        fi
      else
        printf '%s\n' "missing_unexpected_absence"
      fi
      ;;
  esac
}

write_missing_artifact_receipt() {
  local exit_code="${1:-0}"
  local reason_id
  local missing_paths=()

  [[ -f "$baseline_path" ]] || missing_paths+=("baseline.json")
  [[ -f "$relation_report_path" ]] || missing_paths+=("relation_report.json")
  [[ -f "$relation_events_path" ]] || missing_paths+=("relation_events.jsonl")
  [[ -f "$evidence_path" ]] || missing_paths+=("metamorphic_evidence.jsonl")
  [[ -f "$drift_digest_path" ]] || missing_paths+=("drift_digest.md")

  if [[ "${#missing_paths[@]}" -eq 0 ]]; then
    rm -f "$missing_artifact_receipt_path"
    return 0
  fi

  reason_id="$(select_missing_artifact_reason_id "$exit_code")"
  emit_missing_artifact_receipt "$reason_id" "${missing_paths[@]}"
}

validate_relation_report_contract() {
  local actual_schema actual_taxonomy
  actual_schema="$(jq -r '.schema_version // empty' "$relation_report_path")"
  actual_taxonomy="$(jq -r '.taxonomy_version // empty' "$relation_report_path")"

  if [[ "$actual_schema" != "$report_schema_version" ]]; then
    echo "parser oracle relation report schema mismatch: expected=${report_schema_version} actual=${actual_schema}" >&2
    return 1
  fi

  if [[ "$actual_taxonomy" != "$taxonomy_version" ]]; then
    echo "parser oracle relation report taxonomy mismatch: expected=${taxonomy_version} actual=${actual_taxonomy}" >&2
    return 1
  fi
}

generate_drift_digest() {
  local actual_schema actual_taxonomy generated_at
  actual_schema="$(jq -r '.schema_version // "unknown"' "$relation_report_path")"
  actual_taxonomy="$(jq -r '.taxonomy_version // "unknown"' "$relation_report_path")"
  generated_at="$(date -u +%Y-%m-%dT%H:%M:%SZ)"

  {
    echo "# Parser Oracle Drift Digest"
    echo
    echo "- generated_at_utc: ${generated_at}"
    echo "- report_schema_version: ${actual_schema}"
    echo "- taxonomy_version: ${actual_taxonomy}"
    echo "- remediation_map_version: ${remediation_map_version}"
    echo "- trace_id: ${trace_id}"
    echo "- decision_id: ${decision_id}"
    echo "- policy_id: ${policy_id}"
    echo
    echo "## Ranked Drift Classes"
    echo
    echo "| rank | drift_class | count | remediation |"
    echo "| --- | --- | ---: | --- |"
    local class_rows class_rank
    class_rows="$(jq -r '
      .fixture_results
      | group_by(.drift_class)
      | map({drift_class: .[0].drift_class, count: length})
      | sort_by(-.count, .drift_class)
      | .[]
      | "\(.drift_class)\t\(.count)"
    ' "$relation_report_path")"
    if [[ -z "$class_rows" ]]; then
      echo "| 1 | equivalent | 0 | none |"
    else
      class_rank=1
      while IFS=$'\t' read -r drift_class drift_count; do
        [[ -n "$drift_class" ]] || continue
        echo "| ${class_rank} | ${drift_class} | ${drift_count} | $(remediation_for_class "$drift_class") |"
        class_rank=$((class_rank + 1))
      done <<<"$class_rows"
    fi
    echo
    echo "## Divergence Clusters"
    echo
    echo "| rank | drift_cluster_id | family_id | owner_hint | drift_count | drift_classes | replay_command |"
    echo "| --- | --- | --- | --- | ---: | --- | --- |"
    local family_rows family_rank
    family_rows="$(jq -r '
      .fixture_results
      | map(select(.drift_class != "equivalent"))
      | group_by(.family_id)
      | map({
          family_id: .[0].family_id,
          drift_count: length,
          drift_classes: (map(.drift_class) | unique | join(",")),
          replay_command: (.[0].replay_command // "n/a")
        })
      | sort_by(-.drift_count, .family_id)
      | .[]
      | "\(.family_id)\t\(.drift_count)\t\(.drift_classes)\t\(.replay_command)"
    ' "$relation_report_path")"
    if [[ -z "$family_rows" ]]; then
      echo "| 1 | cluster:none | none | parser-frontier | 0 | equivalent | n/a |"
    else
      family_rank=1
      while IFS=$'\t' read -r family_id drift_count drift_classes replay_command; do
        [[ -n "$family_id" ]] || continue
        echo "| ${family_rank} | cluster:${family_id} | ${family_id} | $(owner_hint_for_family "$family_id") | ${drift_count} | ${drift_classes} | \`${replay_command}\` |"
        family_rank=$((family_rank + 1))
      done <<<"$family_rows"
    fi
  } >"$drift_digest_path"
}

declare -a commands_run=()
failed_command=""
manifest_written=false
last_command_log_path=""

command_log_name() {
  local command_text="$1"
  local index="$2"
  local sanitized
  sanitized="$(printf '%s' "$command_text" | tr ' /:|()' '_' | tr -cd '[:alnum:]_.-' | cut -c1-120)"
  printf '%03d_%s.log\n' "$index" "$sanitized"
}

run_step() {
  local command_text="$1"
  local log_path remote_exit_code command_index command_log_path
  shift
  commands_run+=("$command_text")
  command_index=$(( ${#commands_run[@]} - 1 ))
  command_log_path="${command_logs_dir}/$(command_log_name "$command_text" "$command_index")"
  echo "==> $command_text"

  log_path="$(mktemp)"
  if ! run_rch "$@" > >(tee "$log_path") 2>&1; then
    remote_exit_code="$(rch_remote_exit_code "$log_path" || true)"

    if [[ "$remote_exit_code" == "0" ]]; then
      echo "==> recovered: remote execution succeeded; artifact retrieval timed out" \
        | tee -a "$log_path"
    elif [[ -n "$remote_exit_code" ]]; then
      cp "$log_path" "$command_log_path"
      rm -f "$log_path"
      failed_command="${command_text} (remote-exit=${remote_exit_code})"
      return 1
    elif rch_strip_ansi "$log_path" | rg -qi -e "timed out|timeout after|signal: terminated|terminated by timeout"; then
      cp "$log_path" "$command_log_path"
      rm -f "$log_path"
      failed_command="${command_text} (timeout=${rch_timeout_seconds}s)"
      return 1
    else
      cp "$log_path" "$command_log_path"
      rm -f "$log_path"
      failed_command="$command_text"
      return 1
    fi
  fi

  if ! rch_reject_local_fallback "$log_path"; then
    cp "$log_path" "$command_log_path"
    rm -f "$log_path"
    failed_command="${command_text} (rch-local-fallback-detected)"
    return 1
  fi

  remote_exit_code="$(rch_remote_exit_code "$log_path" || true)"
  if [[ -n "$remote_exit_code" && "$remote_exit_code" != "0" ]]; then
    cp "$log_path" "$command_log_path"
    rm -f "$log_path"
    failed_command="${command_text} (remote-exit=${remote_exit_code})"
    return 1
  fi

  cp "$log_path" "$command_log_path"
  last_command_log_path="$command_log_path"
  rm -f "$log_path"
}

write_supporting_artifacts() {
  local git_commit kernel os_name arch cpu_model cpu_feature_profile cores mem_kb mem_bytes
  local rustc_version cargo_version deterministic_env_version toolchain_fingerprint
  git_commit="$(git rev-parse HEAD 2>/dev/null || echo "unknown")"
  kernel="$(uname -r)"
  os_name="$(uname -s | tr '[:upper:]' '[:lower:]')"
  arch="$(uname -m)"
  cpu_model="$(grep -m1 'model name' /proc/cpuinfo 2>/dev/null | sed 's/.*: //')"
  [[ -n "$cpu_model" ]] || cpu_model="unknown"
  cpu_feature_profile="$(grep -m1 '^flags' /proc/cpuinfo 2>/dev/null | sed 's/^[^:]*:[[:space:]]*//')"
  [[ -n "$cpu_feature_profile" ]] || cpu_feature_profile="unknown"
  cores="$(nproc 2>/dev/null || echo 0)"
  mem_kb="$(awk '/MemTotal/ {print $2}' /proc/meminfo 2>/dev/null || echo 0)"
  mem_bytes="$((mem_kb * 1024))"
  rustc_version="$(rustc --version | sed 's/^rustc //')"
  cargo_version="$(cargo --version | sed 's/^cargo //')"
  deterministic_env_version="${PARSER_ORACLE_ENV_BOOTSTRAP_VERSION:-franken-engine.parser-oracle.env-bootstrap.v1}"
  toolchain_fingerprint="${toolchain}|rustc:${rustc_version}|cargo:${cargo_version}"

  jq -n \
    --arg captured_at "$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
    --arg commit "$git_commit" \
    --arg os "$os_name" \
    --arg kernel "$kernel" \
    --arg arch "$arch" \
    --arg cpu_model "$cpu_model" \
    --arg cpu_feature_profile "$cpu_feature_profile" \
    --argjson cores "$cores" \
    --argjson memory_bytes "$mem_bytes" \
    --arg rustc "$rustc_version" \
    --arg cargo "$cargo_version" \
    --arg report_schema_version "$report_schema_version" \
    --arg taxonomy_version "$taxonomy_version" \
    --arg remediation_map_version "$remediation_map_version" \
    --arg deterministic_env_version "$deterministic_env_version" \
    --arg toolchain_fingerprint "$toolchain_fingerprint" \
    '{
      schema_version: "franken-engine.env.v1",
      captured_at_utc: $captured_at,
      project: { name: "franken_engine", commit: $commit, branch: "main" },
      host: {
        os: $os,
        kernel: $kernel,
        arch: $arch,
        cpu_model: $cpu_model,
        cpu_feature_profile: $cpu_feature_profile,
        cpu_cores_logical: $cores,
        memory_bytes: $memory_bytes
      },
      toolchain: {
        rustc: $rustc,
        cargo: $cargo,
        target_dir: env.CARGO_TARGET_DIR,
        fingerprint: $toolchain_fingerprint
      },
      parser_oracle: {
        partition: env.PARSER_ORACLE_PARTITION,
        gate_mode: env.PARSER_ORACLE_GATE_MODE,
        fixture_catalog: env.PARSER_ORACLE_FIXTURE_CATALOG,
        report_schema_version: $report_schema_version,
        taxonomy_version: $taxonomy_version,
        remediation_map_version: $remediation_map_version,
        deterministic_env_schema_version: $deterministic_env_version
      }
    }' >"$env_path"

  local equivalent minor critical action fallback
  local receipt_reason_id receipt_reason_code receipt_consumer_action receipt_stage
  local outputs_json checksum_path checksum_value
  outputs_json='[]'

  if [[ -f "$relation_report_path" ]]; then
    equivalent="$(jq -r '.summary.equivalent_count // 0' "$relation_report_path")"
    minor="$(jq -r '.summary.minor_drift_count // 0' "$relation_report_path")"
    critical="$(jq -r '.summary.critical_drift_count // 0' "$relation_report_path")"
    action="$(jq -r '.decision.action // "unknown"' "$relation_report_path")"
    fallback="$(jq -r '.decision.fallback_reason // "none"' "$relation_report_path")"

    cat >"$proof_note_path" <<EOF_NOTE
# Parser Oracle Proof Note

- trace_id: ${trace_id}
- decision_id: ${decision_id}
- policy_id: ${policy_id}
- partition: ${partition}
- gate_mode: ${gate_mode}
- fixture_catalog: ${fixture_catalog}
- report_schema_version: ${report_schema_version}
- taxonomy_version: ${taxonomy_version}
- remediation_map_version: ${remediation_map_version}
- toolchain_fingerprint: ${toolchain_fingerprint}

## Drift Summary

- equivalent_count: ${equivalent}
- minor_drift_count: ${minor}
- critical_drift_count: ${critical}
- decision_action: ${action}
- fallback_reason: ${fallback}

## Replay

\`\`\`bash
cargo run -p frankenengine-engine --bin franken_parser_oracle_report -- \
  --partition ${partition} \
  --gate-mode ${gate_mode} \
  --seed ${seed} \
  --trace-id ${trace_id} \
  --decision-id ${decision_id} \
  --policy-id ${policy_id} \
  --fixture-catalog ${fixture_catalog}
\`\`\`
EOF_NOTE
  else
    receipt_reason_id="$(jq -r '.reason_id // "unknown"' "$missing_artifact_receipt_path")"
    receipt_reason_code="$(jq -r '.reason_code // "unknown"' "$missing_artifact_receipt_path")"
    receipt_consumer_action="$(jq -r '.consumer_action // "unknown"' "$missing_artifact_receipt_path")"
    receipt_stage="$(jq -r '.stage // "unknown"' "$missing_artifact_receipt_path")"

    cat >"$proof_note_path" <<EOF_NOTE
# Parser Oracle Proof Note

- trace_id: ${trace_id}
- decision_id: ${decision_id}
- policy_id: ${policy_id}
- partition: ${partition}
- gate_mode: ${gate_mode}
- fixture_catalog: ${fixture_catalog}
- report_schema_version: ${report_schema_version}
- taxonomy_version: ${taxonomy_version}
- remediation_map_version: ${remediation_map_version}
- toolchain_fingerprint: ${toolchain_fingerprint}

## Missing-Artifact Receipt

- receipt_path: ${missing_artifact_receipt_path}
- reason_id: ${receipt_reason_id}
- reason_code: ${receipt_reason_code}
- stage: ${receipt_stage}
- consumer_action: ${receipt_consumer_action}

## Replay

\`\`\`bash
./scripts/run_parser_oracle_gate.sh ${mode}
\`\`\`
EOF_NOTE
  fi

  for checksum_path in \
    "$baseline_path" \
    "$relation_report_path" \
    "$relation_events_path" \
    "$evidence_path" \
    "$drift_digest_path" \
    "$missing_artifact_receipt_path"; do
    [[ -f "$checksum_path" ]] || continue
    checksum_value="$(sha256sum "$checksum_path" | awk '{print $1}')"
    outputs_json="$(
      jq -c \
        --arg path "$checksum_path" \
        --arg sha "sha256:${checksum_value}" \
        '. + [{path: $path, sha256: $sha}]' \
        <<<"$outputs_json"
    )"
  done

  jq -n \
    --arg schema_version "franken-engine.repro-lock.v1" \
    --arg generated_at_utc "$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
    --arg lock_id "parser-oracle-${timestamp}" \
    --arg source_commit "${git_commit}" \
    --arg partition "${partition}" \
    --arg gate_mode "${gate_mode}" \
    --arg commands_log "${commands_path}" \
    --arg fixture_catalog "${fixture_catalog}" \
    --argjson seed "${seed}" \
    --argjson outputs "$outputs_json" \
    '{
      schema_version: $schema_version,
      generated_at_utc: $generated_at_utc,
      lock_id: $lock_id,
      source_commit: $source_commit,
      partition: $partition,
      gate_mode: $gate_mode,
      seed: $seed,
      commands_log: $commands_log,
      inputs: [{path: $fixture_catalog}],
      outputs: $outputs
    }' >"$repro_lock_path"

  : >"$golden_checksums_path"
  for checksum_path in \
    "$baseline_path" \
    "$relation_report_path" \
    "$relation_events_path" \
    "$evidence_path" \
    "$drift_digest_path" \
    "$missing_artifact_receipt_path" \
    "$env_path" \
    "$proof_note_path" \
    "$repro_lock_path"; do
    [[ -f "$checksum_path" ]] || continue
    checksum_value="$(sha256sum "$checksum_path" | awk '{print $1}')"
    printf '%s  %s\n' "$checksum_value" "$checksum_path" >>"$golden_checksums_path"
  done
}

write_manifest() {
  local exit_code="${1:-0}"
  local outcome error_code_json git_commit dirty_worktree idx comma

  if [[ "$manifest_written" == true ]]; then
    return
  fi
  manifest_written=true

  if [[ "$exit_code" -eq 0 ]]; then
    outcome="pass"
    error_code_json="null"
  else
    outcome="fail"
    error_code_json='"FE-PARSER-ORACLE-0001"'
  fi

  write_placeholders
  write_supporting_artifacts

  git_commit="$(git rev-parse HEAD 2>/dev/null || echo "unknown")"
  if git diff --quiet --ignore-submodules HEAD -- >/dev/null 2>&1; then
    dirty_worktree=false
  else
    dirty_worktree=true
  fi

  printf '%s\n' "${commands_run[@]}" >"$commands_path"
  {
    echo "{\"schema_version\":\"franken-engine.parser-log-event.v1\",\"taxonomy_version\":\"${taxonomy_version}\",\"trace_id\":\"${trace_id}\",\"decision_id\":\"${decision_id}\",\"policy_id\":\"${policy_id}\",\"component\":\"parser_oracle_gate\",\"event\":\"gate_completed\",\"replay_command\":\"./scripts/run_parser_oracle_gate.sh ${mode}\",\"outcome\":\"${outcome}\",\"error_code\":${error_code_json}}"
  } >"$events_path"

  {
    echo "{"
    echo '  "schema_version": "franken-engine.parser-oracle-gate.run-manifest.v1",'
    echo "  \"report_schema_version\": \"${report_schema_version}\","
    echo "  \"taxonomy_version\": \"${taxonomy_version}\","
    echo "  \"remediation_map_version\": \"${remediation_map_version}\","
    echo "  \"deterministic_env_schema_version\": \"${PARSER_ORACLE_ENV_BOOTSTRAP_VERSION:-franken-engine.parser-oracle.env-bootstrap.v1}\","
    echo '  "bead_id": "bd-1b70",'
    echo '  "component": "parser_oracle_gate",'
    echo "  \"mode\": \"${mode}\","
    echo "  \"partition\": \"${partition}\","
    echo "  \"gate_mode\": \"${gate_mode}\","
    echo "  \"seed\": ${seed},"
    echo "  \"toolchain\": \"${toolchain}\","
    echo "  \"cargo_target_dir\": \"${target_dir}\","
    echo "  \"fixture_catalog\": \"${fixture_catalog}\","
    echo "  \"trace_id\": \"${trace_id}\","
    echo "  \"decision_id\": \"${decision_id}\","
    echo "  \"policy_id\": \"${policy_id}\","
    echo "  \"generated_at_utc\": \"${timestamp}\","
    echo "  \"git_commit\": \"${git_commit}\","
    echo "  \"dirty_worktree\": ${dirty_worktree},"
    echo "  \"outcome\": \"${outcome}\","
    if [[ -n "$failed_command" ]]; then
      echo "  \"failed_command\": \"${failed_command}\","
    fi
    echo '  "commands": ['
    for idx in "${!commands_run[@]}"; do
      comma=","
      if [[ "$idx" == "$(( ${#commands_run[@]} - 1 ))" ]]; then
        comma=""
      fi
      echo "    \"${commands_run[$idx]}\"${comma}"
    done
    echo "  ],"
    echo '  "artifacts": {'
    echo "    \"manifest\": \"${manifest_path}\","
    echo "    \"events\": \"${events_path}\","
    echo "    \"commands\": \"${commands_path}\","
    echo "    \"command_logs_dir\": \"${command_logs_dir}\","
    echo "    \"baseline\": \"${baseline_path}\","
    echo "    \"relation_report\": \"${relation_report_path}\","
    echo "    \"relation_events\": \"${relation_events_path}\","
    echo "    \"metamorphic_evidence\": \"${evidence_path}\","
    echo "    \"drift_digest\": \"${drift_digest_path}\","
    echo "    \"minimized_failures_dir\": \"${failures_dir}\","
    echo "    \"golden_checksums\": \"${golden_checksums_path}\","
    echo "    \"proof_note\": \"${proof_note_path}\","
    echo "    \"env\": \"${env_path}\","
    echo "    \"repro_lock\": \"${repro_lock_path}\""
    echo "  }"
    echo "}"
  } >"$manifest_path"

  echo "parser oracle gate manifest: $manifest_path"
}

handle_signal() {
  local signal="$1"
  if [[ "$manifest_written" != true ]]; then
    failed_command="${failed_command:-signal_${signal}}"
    write_manifest 130
  fi
  exit 130
}

trap 'handle_signal INT' INT
trap 'handle_signal TERM' TERM

run_mode() {
  case "$mode" in
    check)
      run_step "cargo check -p frankenengine-engine --lib --bin franken_parser_oracle_report" \
        cargo check -p frankenengine-engine --lib --bin franken_parser_oracle_report || return 1
      ;;
    test)
      run_step "cargo test -p frankenengine-engine --test parser_oracle_gate" \
        cargo test -p frankenengine-engine --test parser_oracle_gate || return 1
      run_step "cargo test -p frankenengine-engine --test parser_phase0_semantic_fixtures --test parser_phase0_metamorphic" \
        cargo test -p frankenengine-engine --test parser_phase0_semantic_fixtures --test parser_phase0_metamorphic || return 1
      ;;
    ci)
      run_step "cargo check -p frankenengine-engine --lib --bin franken_parser_oracle_report" \
        cargo check -p frankenengine-engine --lib --bin franken_parser_oracle_report || return 1
      run_step "cargo test -p frankenengine-engine --test parser_oracle_gate --test parser_phase0_semantic_fixtures --test parser_phase0_metamorphic" \
        cargo test -p frankenengine-engine --test parser_oracle_gate --test parser_phase0_semantic_fixtures --test parser_phase0_metamorphic || return 1

      run_step "cargo run -p frankenengine-engine --bin franken_parser_oracle_report -- --partition ${partition} --gate-mode ${gate_mode} --seed ${seed} --trace-id ${trace_id} --decision-id ${decision_id} --policy-id ${policy_id} --fixture-catalog ${fixture_catalog} --out ${relation_report_path}" \
        cargo run -p frankenengine-engine --bin franken_parser_oracle_report -- \
          --partition "$partition" \
          --gate-mode "$gate_mode" \
          --seed "$seed" \
          --trace-id "$trace_id" \
          --decision-id "$decision_id" \
          --policy-id "$policy_id" \
          --fixture-catalog "$fixture_catalog" \
          --out "$relation_report_path" || return 1

      if ! relation_report_has_contract; then
        if ! recover_relation_report_from_command_log "$last_command_log_path"; then
          failed_command="recover parser oracle relation report from rch command log"
          return 1
        fi
      fi

      if ! validate_relation_report_contract; then
        failed_command="validate parser oracle relation report schema/taxonomy contract"
        return 1
      fi

      jq '{
          schema_version: "franken-engine.parser-oracle.baseline.v1",
          taxonomy_version: .taxonomy_version,
          generated_at_utc,
          parser_mode,
          fixture_catalog_path,
          fixture_catalog_hash,
          partition,
          seed,
          equivalent_count: .summary.equivalent_count,
          minor_drift_count: .summary.minor_drift_count,
          critical_drift_count: .summary.critical_drift_count
        }' "$relation_report_path" >"$baseline_path"

      local pairs
      pairs="$(pairs_for_partition "$partition")"
      run_step "cargo run -p frankenengine-metamorphic --bin run_metamorphic_suite -- --pairs ${pairs} --seed ${seed} --trace-id ${trace_id} --decision-id ${decision_id} --policy-id ${policy_id} --evidence ${evidence_path} --events ${relation_events_path} --failures-dir ${failures_dir} --relation parser_whitespace_invariance --relation parser_comment_invariance --relation parser_parenthesization_invariance --relation parser_asi_equivalence --relation parser_unicode_escape_equivalence --relation parser_source_position_independence" \
        cargo run -p frankenengine-metamorphic --bin run_metamorphic_suite -- \
          --pairs "$pairs" \
          --seed "$seed" \
          --trace-id "$trace_id" \
          --decision-id "$decision_id" \
          --policy-id "$policy_id" \
          --evidence "$evidence_path" \
          --events "$relation_events_path" \
          --failures-dir "$failures_dir" \
          --relation parser_whitespace_invariance \
          --relation parser_comment_invariance \
          --relation parser_parenthesization_invariance \
          --relation parser_asi_equivalence \
          --relation parser_unicode_escape_equivalence \
          --relation parser_source_position_independence || return 1
      generate_drift_digest
      ;;
    *)
      echo "usage: $0 [check|test|ci]" >&2
      exit 2
      ;;
  esac
}

main_exit=0
run_mode || main_exit=$?
write_manifest "$main_exit"

if ! "${root_dir}/scripts/validate_parser_log_schema.sh" --events "$events_path"; then
  failed_command="${failed_command:-validate_parser_log_schema.sh --events ${events_path}}"
  manifest_written=false
  write_manifest 3
  main_exit=3
fi

exit "$main_exit"
