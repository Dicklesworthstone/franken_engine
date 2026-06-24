#!/usr/bin/env bash
set -euo pipefail

root_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "${root_dir}"

artifact_root="${SEMANTIC_FIDELITY_ARTIFACT_ROOT:-artifacts/semantic_fidelity_workbench_gate}"
required_files=(run_manifest.json events.jsonl commands.txt vector_results.jsonl path_parity_report.json auto_triage_report.json summary.md)

usage() {
  cat >&2 <<'EOF'
usage:
  scripts/e2e/semantic_fidelity_workbench_replay.sh [RUN_DIR|latest]

Verifies a preserved semantic-fidelity workbench bundle without rerunning the
runner. Missing, incomplete, malformed, or fail_closed bundles exit nonzero.
EOF
}

is_complete_bundle() {
  local dir="$1" file
  [[ -d "${dir}" ]] || return 1
  for file in "${required_files[@]}"; do
    [[ -f "${dir}/${file}" ]] || return 1
  done
}

newest_bundle_dir() {
  [[ -d "${artifact_root}" ]] || return 0
  find "${artifact_root}" -mindepth 1 -maxdepth 1 -type d 2>/dev/null | sort -r | head -n 1
}

latest_complete_bundle_dir() {
  local candidate
  [[ -d "${artifact_root}" ]] || return 0
  while IFS= read -r candidate; do
    [[ -n "${candidate}" ]] || continue
    if is_complete_bundle "${candidate}"; then
      printf '%s\n' "${candidate}"
      return 0
    fi
  done < <(find "${artifact_root}" -mindepth 1 -maxdepth 1 -type d 2>/dev/null | sort -r)
}

select_bundle_dir() {
  local requested="${1:-latest}"
  if [[ "${requested}" != "latest" ]]; then
    printf '%s\n' "${requested}"
    return 0
  fi

  local latest newest
  latest="$(latest_complete_bundle_dir || true)"
  newest="$(newest_bundle_dir || true)"
  if [[ -z "${latest}" ]]; then
    if [[ -n "${newest}" ]]; then
      printf '[semantic-fidelity replay] newest bundle is incomplete: %s\n' "${newest}" >&2
    fi
    printf '[semantic-fidelity replay] no complete bundle found under %s\n' "${artifact_root}" >&2
    return 1
  fi
  if [[ -n "${newest}" && "${newest}" != "${latest}" ]]; then
    printf '[semantic-fidelity replay] newest bundle %s is incomplete; using latest complete %s\n' \
      "${newest}" "${latest}" >&2
  fi
  printf '%s\n' "${latest}"
}

require_complete() {
  local dir="$1" file missing=0
  [[ -d "${dir}" ]] || {
    printf '[semantic-fidelity replay] bundle directory not found: %s\n' "${dir}" >&2
    return 1
  }
  for file in "${required_files[@]}"; do
    if [[ ! -f "${dir}/${file}" ]]; then
      printf '[semantic-fidelity replay] missing required artifact: %s/%s\n' "${dir}" "${file}" >&2
      missing=1
    fi
  done
  [[ "${missing}" -eq 0 ]]
}

validate_bundle() {
  local dir="$1"
  require_complete "${dir}"

  jq empty "${dir}/run_manifest.json" "${dir}/events.jsonl" "${dir}/vector_results.jsonl"

  [[ -s "${dir}/commands.txt" ]] || {
    printf '[semantic-fidelity replay] commands.txt is empty: %s/commands.txt\n' "${dir}" >&2
    return 1
  }
  [[ -s "${dir}/summary.md" ]] || {
    printf '[semantic-fidelity replay] summary.md is empty: %s/summary.md\n' "${dir}" >&2
    return 1
  }

  jq -e '
    .schema_version == "franken-engine.semantic-fidelity-workbench-run.v1"
    and (.suite_id | type == "string")
    and (.suite_sha256 | startswith("sha256:"))
    and (.artifact_paths.run_manifest == "run_manifest.json")
    and (.artifact_paths.events == "events.jsonl")
    and (.artifact_paths.commands == "commands.txt")
    and (.artifact_paths.vector_results == "vector_results.jsonl")
    and (.artifact_paths.path_parity_report == "path_parity_report.json")
    and (.artifact_paths.auto_triage_report == "auto_triage_report.json")
    and (.artifact_paths.summary == "summary.md")
  ' "${dir}/run_manifest.json" >/dev/null

  jq -e '
    .schema_version == "franken-engine.semantic-fidelity-event.v1"
    and (.event | type == "string")
    and (.generated_at_utc | type == "string")
    and (.outcome | type == "string")
    and (if .event == "vector_evaluated" then
      (.source_sha256 | startswith("sha256:"))
      and (.dispatch_route.route_id | type == "string")
      and (.dispatch_route.route_kind | type == "string")
      and (.expected_outcome.kind | type == "string")
      and (.actual_outcome.kind | type == "string")
      and (.command_replay_hints.vector_id == .vector_id)
      and (.command_replay_hints.preserved_bundle_replay | contains("semantic_fidelity_workbench_replay.sh"))
      and ((.first_divergence == null) or (.first_divergence.reason_code | type == "string"))
    else true end)
  ' "${dir}/events.jsonl" >/dev/null

  local decision result_count
  decision="$(jq -r '.decision // empty' "${dir}/run_manifest.json")"
  result_count="$(jq -s 'length' "${dir}/vector_results.jsonl")"
  case "${decision}" in
    supported|degraded|supported_with_non_passing_vectors)
      if [[ "${result_count}" -lt 1 ]]; then
        printf '[semantic-fidelity replay] accepted decision has no vector results: %s\n' "${dir}" >&2
        return 1
      fi
      jq -e '
        .schema_version == "franken-engine.semantic-fidelity-vector-result.v1"
        and (.vector_id | type == "string")
        and (.source_sha256 | startswith("sha256:"))
        and (.route_id | type == "string")
        and (.dispatch_route.route_id | type == "string")
        and (.dispatch_route.route_kind | type == "string")
        and (.expectation_kind | type == "string")
        and (.expected_outcome.kind | type == "string")
        and (.actual_outcome.kind | type == "string")
        and (.outcome | type == "string")
        and (.passed | type == "boolean")
        and (.reason_codes | type == "array")
        and (.evidence_classification | type == "string")
        and (.command_replay_hints.vector_id == .vector_id)
        and (.command_replay_hints.runner_command | contains("semantic_fidelity_workbench.py"))
        and (.command_replay_hints.preserved_bundle_replay | contains("semantic_fidelity_workbench_replay.sh"))
        and ((.first_divergence == null) or (.first_divergence.reason_code | type == "string"))
      ' "${dir}/vector_results.jsonl" >/dev/null
      ;;
    fail_closed)
      printf '[semantic-fidelity replay] bundle decision is fail_closed: %s\n' "${dir}" >&2
      return 1
      ;;
    *)
      printf '[semantic-fidelity replay] unknown or missing decision %q in %s\n' "${decision}" "${dir}" >&2
      return 1
      ;;
  esac

  if jq -e '(.validation_errors // []) | length > 0' "${dir}/run_manifest.json" >/dev/null; then
    printf '[semantic-fidelity replay] bundle has validation_errors: %s\n' "${dir}" >&2
    return 1
  fi

  jq -e '
    .schema_version == "franken-engine.semantic-fidelity-path-parity-report.v1"
    and (.suite_id | type == "string")
    and (.summary.vector_count | type == "number")
    and (.summary.builtin_group_count | type == "number")
    and (.summary.route_disagreement_group_count | type == "number")
    and (.groups | type == "array")
    and (.failure_groups | type == "array")
    and all(.groups[];
      (.builtin | type == "string")
      and (.semantic_family | type == "string")
      and (.group_status | type == "string")
      and (.route_disagreement | type == "boolean")
      and (.routes | type == "array")
      and (.source_route_disagreements | type == "array")
      and all(.source_route_disagreements[];
        (.source_sha256 | startswith("sha256:"))
        and (.route_count | type == "number")
        and (.actual_signatures | type == "array")
        and (.routes | type == "array"))
      and all(.routes[];
        (.source_sha256 | startswith("sha256:"))
        and (.dispatch_route.route_id | type == "string")
        and (.expected_signature | type == "string")
        and (.actual_signature | type == "string")
        and ((.first_divergence == null) or (.first_divergence.reason_code | type == "string"))))
  ' "${dir}/path_parity_report.json" >/dev/null

  jq -e '
    .schema_version == "franken-engine.semantic-fidelity-auto-triage-report.v1"
    and (.suite_id | type == "string")
    and (.summary.entry_count | type == "number")
    and (.summary.confirmed_failure_count | type == "number")
    and (.summary.existing_bead_link_count | type == "number")
    and (.summary.suggested_bead_count | type == "number")
    and (.summary.unsupported_surface_count | type == "number")
    and (.summary.degraded_surface_count | type == "number")
    and (.entries | type == "array")
    and all(.entries[];
      (.vector_id | type == "string")
      and (.semantic_family | type == "string")
      and (.builtin | type == "string")
      and (.dispatch_route.route_id | type == "string")
      and (.triage_classification | type == "string")
      and (.triage_action | type == "string")
      and (.existing_beads | type == "array")
      and ((.suggested_bead == null) or
        ((.suggested_bead.title | type == "string")
        and (.suggested_bead.description | contains("## Background"))
        and (.suggested_bead.description | contains("## Validation"))))
      and (.validation_commands.vector_id == .vector_id))
  ' "${dir}/auto_triage_report.json" >/dev/null
}

requested="${1:-latest}"
case "${requested}" in
  -h|--help|help)
    usage
    exit 0
    ;;
esac

bundle_dir="$(select_bundle_dir "${requested}")"
validate_bundle "${bundle_dir}"
printf '[semantic-fidelity replay] PASS bundle: %s\n' "${bundle_dir}"
