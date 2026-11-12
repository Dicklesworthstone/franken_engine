#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "${repo_root}" || exit 1

frankenctl_bin="${FRANKENCTL_BIN:-}"
if [[ -z "${frankenctl_bin}" && -x "target/release/frankenctl" ]]; then
  frankenctl_bin="target/release/frankenctl"
fi

if ! command -v jq >/dev/null 2>&1; then
  printf 'jq is required for external trust explanation goldens smoke\n' >&2
  exit 2
fi

workdir="$(mktemp -d "${TMPDIR:-/tmp}/external-trust-goldens.XXXXXX")"
events_log="${workdir}/events.jsonl"
: >"${events_log}"

log_and_fail() {
  local suite="$1"
  local case_id="$2"
  local fixture_path="$3"
  local cmd_line="$4"
  local receipt_file="$5"
  local msg="$6"
  local decision="unknown"
  local reasons="[]"
  local art_hash="null"
  if [[ -f "${receipt_file}" ]]; then
    decision="$(jq -r '.decision // "unknown"' "${receipt_file}" 2>/dev/null || echo unknown)"
    reasons="$(jq -c '.reason_codes // []' "${receipt_file}" 2>/dev/null || echo '[]')"
    art_hash="$(jq -r '(.artifact.content_hash // .bundle.content_hash // .e8_scenario.contract_hash_hex // "null")' "${receipt_file}" 2>/dev/null || echo null)"
  fi
  printf 'FAIL [%s/%s]: %s\n  fixture_path: %s\n  command_line: %s\n  decision: %s\n  reason_codes: %s\n  artifact_hash: %s\n' \
    "${suite}" "${case_id}" "${msg}" "${fixture_path}" "${cmd_line}" "${decision}" "${reasons}" "${art_hash}" >&2
  exit 1
}

scrub_claim_receipt() {
  local in_file="$1"
  local root_dir="$2"
  local out_file="$3"
  jq --arg root "${root_dir}" '
    walk(
      if type == "string" then
        gsub($root; "<WORKDIR>")
      else
        .
      end
    )
    | .generated_at_utc = "<GENERATED_AT_UTC>"
    | .receipt_id = "claim-explain-<SCRUBBED>"
    | if .artifact != null and (.artifact | has("age_days")) then .artifact.age_days = 0 else . end
  ' "${in_file}" >"${out_file}"
}

# 1. Bundle doctor suite (28 cases + healthy golden)
bash scripts/e2e/external_trust_artifact_bundle_doctor_smoke.sh

# 2. E8 non-use certificate scenario report suite (10 cases + JSON/text goldens)
bash scripts/e2e/e8_non_use_certificate_scenario_report_smoke.sh

# 3. Claim explainer suite + scrubbed goldens
if [[ -z "${frankenctl_bin}" || ! -x "${frankenctl_bin}" ]]; then
  printf 'SKIP claim explainer binary execution (FRANKENCTL_BIN not provided); checking golden JSON syntax only\n'
  for g in \
    scripts/testdata/goldens/external_trust_claim_explainer_observed_supported.golden \
    scripts/testdata/goldens/external_trust_claim_explainer_target_not_promotable.golden \
    scripts/testdata/goldens/external_trust_claim_explainer_owning_bead_mismatch.golden; do
    jq empty "${g}"
  done
  exit 0
fi

claim_fixture="${workdir}/claim_fixture"
mkdir -p "${claim_fixture}/stale_bundle"
printf '{"proof":"observed"}\n' >"${claim_fixture}/artifact.json"
printf 'fixture repro lock\n' >"${claim_fixture}/repro.lock"
printf 'Golden smoke source claim.\n' >"${claim_fixture}/source.md"
cat >"${claim_fixture}/stale_bundle/manifest.json" <<'JSON'
{
  "schema_version": "franken-engine.proof-artifact-manifest.v1",
  "freshness": {
    "generated_utc": "2020-01-01T00:00:00Z"
  }
}
JSON
printf 'fixture repro lock\n' >"${claim_fixture}/stale_bundle/repro.lock"

jq -n \
  --arg artifact_path "${claim_fixture}/artifact.json" \
  --arg stale_path "${claim_fixture}/stale_bundle" \
  --arg source_path "${claim_fixture}/source.md" \
  '{
    schema_version: "franken-engine.claim-to-proof-matrix.v1",
    stale_threshold_days: 30,
    claims: [
      {
        actual_wording_state: "observed",
        allowed_state: "observed",
        artifact_path: $artifact_path,
        claim_id: "FE-CLAIM-OBSERVED-PASS",
        claim_scope: "evidence",
        claim_text: "Golden smoke source claim.",
        decision: "allow observed fixture",
        downgrade_text: "Downgrade observed fixture.",
        freshness_days: 0,
        owning_bead: "bd-closed-owner",
        reason: "Observed fixture verified.",
        source_path: $source_path,
        source_span: { start_line: 1, end_line: 1, must_contain: "Golden smoke" },
        verification_command: "rch exec -- env CARGO_TARGET_DIR=/data/tmp/rch_smoke cargo test -p frankenengine-engine smoke"
      },
      {
        actual_wording_state: "target",
        allowed_state: "target",
        artifact_path: "nonexistent_target_artifact.json",
        claim_id: "FE-CLAIM-TARGET-HYPOTHESIS",
        claim_scope: "evidence",
        claim_text: "Golden smoke source claim.",
        decision: "keep target claim unpromoted",
        downgrade_text: "Target-only; not observed.",
        freshness_days: 0,
        owning_bead: "bd-open-owner",
        reason: "Target hypothesis pending proof.",
        source_path: $source_path,
        source_span: { start_line: 1, end_line: 1, must_contain: "Golden smoke" },
        verification_command: "rch exec -- env CARGO_TARGET_DIR=/data/tmp/rch_smoke cargo test -p frankenengine-engine smoke"
      },
      {
        actual_wording_state: "observed",
        allowed_state: "observed",
        artifact_path: $stale_path,
        claim_id: "FE-CLAIM-STALE-ARTIFACT",
        claim_scope: "evidence",
        claim_text: "Golden smoke source claim.",
        decision: "reject stale artifact",
        downgrade_text: "Stale evidence.",
        freshness_days: 0,
        owning_bead: "bd-closed-owner",
        reason: "Stale check.",
        source_path: $source_path,
        source_span: { start_line: 1, end_line: 1, must_contain: "Golden smoke" },
        verification_command: "rch exec -- env CARGO_TARGET_DIR=/data/tmp/rch_smoke cargo test -p frankenengine-engine smoke"
      },
      {
        actual_wording_state: "observed",
        allowed_state: "observed",
        artifact_path: $artifact_path,
        claim_id: "FE-CLAIM-OWNING-BEAD-MISMATCH",
        claim_scope: "evidence",
        claim_text: "Golden smoke source claim.",
        decision: "reject open owning bead",
        downgrade_text: "Owning bead still open.",
        freshness_days: 0,
        owning_bead: "bd-open-owner",
        reason: "Bead status check.",
        source_path: $source_path,
        source_span: { start_line: 1, end_line: 1, must_contain: "Golden smoke" },
        verification_command: "rch exec -- env CARGO_TARGET_DIR=/data/tmp/rch_smoke cargo test -p frankenengine-engine smoke"
      }
    ]
  }' >"${claim_fixture}/matrix.json"

jq -cn '{id:"bd-closed-owner", status:"closed", assignee:"ubuntu"}' >"${claim_fixture}/issues.jsonl"
jq -cn '{id:"bd-open-owner", status:"open", assignee:"ubuntu"}' >>"${claim_fixture}/issues.jsonl"

run_claim_case() {
  local case_id="$1"
  local claim_id="$2"
  local expected_rc="$3"
  local expected_decision="$4"
  local expected_reason="$5"
  local golden_path="${6:-}"
  local raw_out="${workdir}/${case_id}.raw.json"
  local scrubbed_out="${workdir}/${case_id}.scrubbed.json"
  local cmd="${frankenctl_bin} claims explain ${claim_id} --matrix ${claim_fixture}/matrix.json --beads-jsonl ${claim_fixture}/issues.jsonl --format json --out ${raw_out}"

  set +e
  "${frankenctl_bin}" claims explain "${claim_id}" \
    --matrix "${claim_fixture}/matrix.json" \
    --beads-jsonl "${claim_fixture}/issues.jsonl" \
    --format json \
    --out "${raw_out}"
  local rc=$?
  set -e

  if [[ "${rc}" -ne "${expected_rc}" ]]; then
    log_and_fail "claim-explainer" "${case_id}" "${claim_fixture}/matrix.json" "${cmd}" "${raw_out}" "exit ${rc} != ${expected_rc}"
  fi
  local dec
  dec="$(jq -r '.decision' "${raw_out}")"
  if [[ "${dec}" != "${expected_decision}" ]]; then
    log_and_fail "claim-explainer" "${case_id}" "${claim_fixture}/matrix.json" "${cmd}" "${raw_out}" "decision ${dec} != ${expected_decision}"
  fi
  if [[ -n "${expected_reason}" ]]; then
    if ! jq -e --arg r "${expected_reason}" '(.reason_codes | index($r)) != null' "${raw_out}" >/dev/null; then
      log_and_fail "claim-explainer" "${case_id}" "${claim_fixture}/matrix.json" "${cmd}" "${raw_out}" "missing reason ${expected_reason}"
    fi
  fi

  scrub_claim_receipt "${raw_out}" "${claim_fixture}" "${scrubbed_out}"
  if [[ "${UPDATE_EXTERNAL_TRUST_GOLDENS:-0}" == "1" && -n "${golden_path}" ]]; then
    cp "${scrubbed_out}" "${golden_path}"
  elif [[ -n "${golden_path}" ]]; then
    if ! diff -u "${golden_path}" "${scrubbed_out}"; then
      log_and_fail "claim-explainer" "${case_id}" "${claim_fixture}/matrix.json" "${cmd}" "${raw_out}" "scrubbed golden mismatch (${golden_path})"
    fi
  fi
}

run_claim_case "observed-pass" "FE-CLAIM-OBSERVED-PASS" 0 "supported" "" \
  "scripts/testdata/goldens/external_trust_claim_explainer_observed_supported.golden"
run_claim_case "target-degraded" "FE-CLAIM-TARGET-HYPOTHESIS" 1 "not_promotable" "claim_not_observed" \
  "scripts/testdata/goldens/external_trust_claim_explainer_target_not_promotable.golden"
run_claim_case "missing-claim" "FE-CLAIM-DOES-NOT-EXIST" 2 "fail_closed" "missing_claim_row" ""
run_claim_case "stale-artifact" "FE-CLAIM-STALE-ARTIFACT" 2 "fail_closed" "stale_artifact" ""
run_claim_case "owning-bead-mismatch" "FE-CLAIM-OWNING-BEAD-MISMATCH" 2 "fail_closed" "contradictory_bead_status" \
  "scripts/testdata/goldens/external_trust_claim_explainer_owning_bead_mismatch.golden"

printf 'PASS external trust explanation goldens & unit smoke (workdir=%s)\n' "${workdir}"
