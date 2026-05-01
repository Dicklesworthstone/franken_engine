#!/usr/bin/env bash
set -euo pipefail

PROOF_ARTIFACT_MANIFEST_SCHEMA_VERSION="franken-engine.proof-artifact-manifest.v1"
PROOF_ARTIFACT_REPORT_SCHEMA_VERSION="franken-engine.proof-artifact-report.v1"
PROOF_ARTIFACT_REDACTION_POLICY_SCHEMA_VERSION="franken-engine.proof-artifact-redaction-policy.v1"

proof_contract_redact_text() {
  local text="$1"
  printf '%s' "$text" \
    | sed -E 's/([A-Za-z0-9_]*(TOKEN|SECRET|PASSWORD|CREDENTIAL|AUTH|KEY)[A-Za-z0-9_]*=)[^[:space:]]+/\1<redacted>/g' \
    | sed -E 's/(Bearer )[A-Za-z0-9._~+\/=-]+/\1<redacted>/g'
}

proof_contract_sha256_file() {
  local path="$1"
  if [[ ! -f "$path" ]]; then
    printf ''
    return 0
  fi

  if command -v sha256sum >/dev/null 2>&1; then
    sha256sum "$path" | awk '{print $1}'
  elif command -v shasum >/dev/null 2>&1; then
    shasum -a 256 "$path" | awk '{print $1}'
  else
    openssl dgst -sha256 "$path" | awk '{print $NF}'
  fi
}

proof_contract_csv_json() {
  local csv="${1:-}"
  if [[ -z "$csv" ]]; then
    printf '[]'
    return 0
  fi
  printf '%s' "$csv" | tr ',' '\n' | jq -R 'select(length > 0)' | jq -s .
}

proof_contract_git_revision() {
  git rev-parse --short HEAD 2>/dev/null || printf 'unknown'
}

proof_contract_assert_required_artifacts() {
  local run_dir="$1"
  local events_path="$2"
  local commands_path="$3"

  [[ -d "$run_dir" ]] || return 1
  [[ -f "$events_path" ]] || return 1
  [[ -f "$commands_path" ]] || return 1
}

proof_contract_write_redaction_policy() {
  local policy_path="$1"
  jq -n \
    --arg schema_version "$PROOF_ARTIFACT_REDACTION_POLICY_SCHEMA_VERSION" \
    '{
      schema_version: $schema_version,
      replacement: "<redacted>",
      env_key_fragments: ["TOKEN", "SECRET", "PASSWORD", "CREDENTIAL", "AUTH", "KEY"],
      literal_patterns: ["Bearer <token>"]
    }' >"$policy_path"
}

proof_contract_write_standard_bundle() {
  local run_dir="$1"
  local gate_name="$2"
  local status="$3"
  local rerun_command="$4"
  local source_report_path="$5"
  local events_path="$6"
  local commands_path="$7"
  local bead_ids_csv="${8:-}"
  local claim_ids_csv="${9:-}"
  local failure_count="${10:-}"

  mkdir -p "$run_dir"

  local manifest_path="${run_dir}/manifest.json"
  local report_json_path="${run_dir}/report.json"
  local report_md_path="${run_dir}/report.md"
  local redaction_policy_path="${run_dir}/redaction_policy.json"
  local source_revision
  local generated_utc
  local bundle_id
  local redacted_rerun_command
  local event_count
  local commands_sha256
  local events_sha256
  local source_report_sha256
  local bead_ids_json
  local claim_ids_json
  local verdict

  proof_contract_assert_required_artifacts "$run_dir" "$events_path" "$commands_path"

  source_revision="$(proof_contract_git_revision)"
  generated_utc="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
  bundle_id="${gate_name}-$(basename "$run_dir")"
  redacted_rerun_command="$(proof_contract_redact_text "$rerun_command")"
  event_count="$(wc -l <"$events_path" | tr -d '[:space:]')"
  commands_sha256="$(proof_contract_sha256_file "$commands_path")"
  events_sha256="$(proof_contract_sha256_file "$events_path")"
  source_report_sha256="$(proof_contract_sha256_file "$source_report_path")"
  bead_ids_json="$(proof_contract_csv_json "$bead_ids_csv")"
  claim_ids_json="$(proof_contract_csv_json "$claim_ids_csv")"

  if [[ -z "$failure_count" ]]; then
    failure_count="$(jq -s '[.[] | select((.status // .decision // "") | test("fail|failed|error"))] | length' "$events_path")"
  fi

  if [[ "$status" == "pass" || "$status" == "passed" ]]; then
    verdict="pass"
  elif [[ "$status" == "skipped" ]]; then
    verdict="skipped"
  elif [[ "$status" == "blocked" ]]; then
    verdict="blocked"
  else
    verdict="fail"
  fi

  proof_contract_write_redaction_policy "$redaction_policy_path"

  jq -n \
    --arg schema_version "$PROOF_ARTIFACT_MANIFEST_SCHEMA_VERSION" \
    --arg bundle_id "$bundle_id" \
    --arg gate_name "$gate_name" \
    --arg status "$verdict" \
    --arg generated_utc "$generated_utc" \
    --arg source_revision "$source_revision" \
    --arg rerun_command "$redacted_rerun_command" \
    --arg run_dir "$run_dir" \
    --arg manifest_json "$manifest_path" \
    --arg commands_txt "$commands_path" \
    --arg events_jsonl "$events_path" \
    --arg report_json "$report_json_path" \
    --arg report_md "$report_md_path" \
    --arg redaction_policy_json "$redaction_policy_path" \
    --arg source_report_path "$source_report_path" \
    --arg commands_sha256 "$commands_sha256" \
    --arg events_sha256 "$events_sha256" \
    --arg source_report_sha256 "$source_report_sha256" \
    --argjson bead_ids "$bead_ids_json" \
    --argjson claim_ids "$claim_ids_json" \
    '{
      schema_version: $schema_version,
      bundle_id: $bundle_id,
      gate_name: $gate_name,
      status: $status,
      generated_utc: $generated_utc,
      source_revision: $source_revision,
      rerun_command: $rerun_command,
      artifact_paths: {
        run_dir: $run_dir,
        manifest_json: $manifest_json,
        commands_txt: $commands_txt,
        events_jsonl: $events_jsonl,
        report_json: $report_json,
        report_md: $report_md,
        redaction_policy_json: $redaction_policy_json
      },
      claim_ids: $claim_ids,
      bead_ids: $bead_ids,
      generated_artifacts: [
        { path: $commands_txt, sha256: $commands_sha256, role: "command_transcript" },
        { path: $events_jsonl, sha256: $events_sha256, role: "structured_events" },
        { path: $source_report_path, sha256: $source_report_sha256, role: "source_machine_report" }
      ],
      expected_artifacts: [],
      verifier_outputs: [
        { verifier_id: "proof-artifact-contract", output_path: $report_json, status: $status, decision: $status }
      ],
      freshness: {
        generated_utc: $generated_utc,
        freshness_days: 0,
        max_freshness_days: 30
      }
    }' >"$manifest_path"

  jq -n \
    --arg schema_version "$PROOF_ARTIFACT_REPORT_SCHEMA_VERSION" \
    --arg bundle_id "$bundle_id" \
    --arg gate_name "$gate_name" \
    --arg status "$verdict" \
    --argjson event_count "$event_count" \
    --argjson failure_count "$failure_count" \
    --arg rerun_command "$redacted_rerun_command" \
    --arg manifest_path "$manifest_path" \
    --arg report_json_path "$report_json_path" \
    --arg report_md_path "$report_md_path" \
    --arg source_report_path "$source_report_path" \
    '{
      schema_version: $schema_version,
      bundle_id: $bundle_id,
      gate_name: $gate_name,
      status: $status,
      event_count: $event_count,
      failure_count: $failure_count,
      rerun_command: $rerun_command,
      manifest_path: $manifest_path,
      report_json_path: $report_json_path,
      report_md_path: $report_md_path,
      source_report_path: $source_report_path,
      findings: []
    }' >"$report_json_path"

  {
    printf '# Proof Artifact Report\n\n'
    printf -- '- Bundle: `%s`\n' "$bundle_id"
    printf -- '- Gate: `%s`\n' "$gate_name"
    printf -- '- Status: `%s`\n' "$verdict"
    printf -- '- Events: `%s`\n' "$event_count"
    printf -- '- Failures: `%s`\n' "$failure_count"
    printf -- '- Rerun: `%s`\n' "$redacted_rerun_command"
    printf -- '- Manifest: `%s`\n' "$manifest_path"
    printf -- '- Machine report: `%s`\n' "$report_json_path"
    printf '\n'
    if [[ "$verdict" == "pass" ]]; then
      printf 'The proof bundle satisfies the shared artifact contract.\n'
    else
      printf 'The proof bundle is not an observed proof until the failing or blocked rows are remediated.\n'
    fi
  } >"$report_md_path"
}
