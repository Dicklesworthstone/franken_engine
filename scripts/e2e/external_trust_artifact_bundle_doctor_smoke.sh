#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "${repo_root}"

doctor="scripts/external_trust_artifact_bundle_doctor.py"
cases_json="scripts/testdata/external_trust_artifact_bundle_doctor/cases.json"
golden="scripts/testdata/goldens/external_trust_artifact_bundle_doctor_healthy.golden"
now_utc="2030-01-01T00:00:00Z"

if ! command -v jq >/dev/null 2>&1; then
  printf 'jq is required for external trust artifact bundle doctor smoke test\n' >&2
  exit 2
fi

tmp_dir="$(mktemp -d "${TMPDIR:-/tmp}/external-trust-bundle-doctor.XXXXXX")"

case_count="$(jq 'length' "${cases_json}")"
for idx in $(seq 0 "$((case_count - 1))"); do
  case_id="$(jq -r ".[$idx].case_id" "${cases_json}")"
  bundle_path="$(jq -r ".[$idx].bundle_path" "${cases_json}")"
  expected_decision="$(jq -r ".[$idx].expected_decision" "${cases_json}")"
  expected_reasons="$(jq -c ".[$idx].expected_reason_codes" "${cases_json}")"
  output_path="${tmp_dir}/${case_id}.json"

  set +e
  BUNDLE_DOCTOR_NOW_UTC="${now_utc}" python3 "${doctor}" --pretty --bundle "${bundle_path}" >"${output_path}"
  rc=$?
  set -e

  decision="$(jq -r '.decision' "${output_path}")"
  if [[ "${decision}" != "${expected_decision}" ]]; then
    printf 'FAIL %s: decision %s != %s\n' "${case_id}" "${decision}" "${expected_decision}" >&2
    cat "${output_path}" >&2
    exit 1
  fi

  case "${decision}" in
    supported|degraded)
      if [[ "${rc}" -ne 0 ]]; then
        printf 'FAIL %s: %s receipt returned %s\n' "${case_id}" "${decision}" "${rc}" >&2
        exit 1
      fi
      ;;
    fail_closed|not_promotable|unsupported)
      if [[ "${rc}" -eq 0 ]]; then
        printf 'FAIL %s: %s receipt returned success\n' "${case_id}" "${decision}" >&2
        exit 1
      fi
      ;;
    *)
      printf 'FAIL %s: unknown decision %s\n' "${case_id}" "${decision}" >&2
      exit 1
      ;;
  esac

  if ! jq -e --argjson expected "${expected_reasons}" \
    '(($expected | sort) == ((.reason_codes // []) | sort))' \
    "${output_path}" >/dev/null; then
    printf 'FAIL %s: reason codes differ from expected set\n' "${case_id}" >&2
    cat "${output_path}" >&2
    exit 1
  fi

  if ! jq -e '
    .schema_version == "franken-engine.external-trust-artifact-bundle-doctor.v1"
    and (.receipt_id | startswith("bundle-doctor-"))
    and .mutation_policy.mutates_br == false
    and .mutation_policy.mutates_agent_mail == false
    and .mutation_policy.mutates_remote_workers == false
    and .mutation_policy.mutates_evidence_bundles == false
    and .renderer_boundary.future_rich_renderer_provider == "/dp/frankentui"
    and (.artifact_refs | type == "array")
  ' "${output_path}" >/dev/null; then
    printf 'FAIL %s: receipt contract predicate failed\n' "${case_id}" >&2
    cat "${output_path}" >&2
    exit 1
  fi
done

BUNDLE_DOCTOR_NOW_UTC="${now_utc}" python3 "${doctor}" --pretty \
  --bundle scripts/testdata/external_trust_artifact_bundle_doctor/healthy \
  >"${tmp_dir}/healthy.golden.actual"

if ! diff -u "${golden}" "${tmp_dir}/healthy.golden.actual"; then
  printf 'FAIL healthy golden changed\n' >&2
  exit 1
fi

printf 'PASS external trust artifact bundle doctor smoke (%s cases; tmp retained at %s)\n' \
  "${case_count}" "${tmp_dir}"
