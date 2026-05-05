#!/usr/bin/env bash
set -euo pipefail

default_root_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
default_contract="${default_root_dir}/docs/rgc_module_composition_claim_ledger_v1.json"

validation_failures=0

record_failure() {
  printf 'FAIL composition-drift %s\n' "$1" >&2
  validation_failures=$((validation_failures + 1))
}

record_pass() {
  printf 'PASS composition-drift %s\n' "$1"
}

path_contains_all_fragments() {
  local abs_path="$1"
  local item_json="$2"
  local fragment

  if [[ ! -f "$abs_path" ]]; then
    return 1
  fi

  while IFS= read -r fragment; do
    [[ -z "$fragment" ]] && continue
    if ! grep -Fq -- "$fragment" "$abs_path"; then
      return 1
    fi
  done < <(jq -r '.fragments[]' <<<"$item_json")

  return 0
}

claim_declares_fallback_for_surface() {
  local claim_json="$1"
  local surface_id="$2"

  jq -e --arg surface_id "$surface_id" '
    any(.allowed_provisional_fallbacks[]?; .surface_id == $surface_id)
  ' <<<"$claim_json" >/dev/null
}

run_drift_check() {
  local contract_path="$1"
  local root_dir="$2"
  local contract_json claim composition_id
  local evidence surface_id rel_path abs_path
  local mode_json mode_id allowed_surface

  validation_failures=0

  if [[ ! -f "$contract_path" ]]; then
    record_failure "reason=missing_contract path=${contract_path}"
    return 1
  fi

  contract_json="$(cat "$contract_path")"

  if ! jq -e '
    .schema_version == "franken-engine.module-composition-claim-ledger.v1"
    and (.claims | type == "array")
    and (.claims | length > 0)
  ' <<<"$contract_json" >/dev/null; then
    record_failure "reason=invalid_top_level_schema path=${contract_path}"
    return 1
  fi

  while IFS= read -r claim; do
    composition_id="$(jq -r '.composition_id' <<<"$claim")"

    if ! jq -e '
      .drift_checks.required_parent_evidence | type == "array"
    ' <<<"$claim" >/dev/null; then
      record_failure "composition=${composition_id} reason=missing_required_parent_evidence_block"
      continue
    fi

    while IFS= read -r evidence; do
      surface_id="$(jq -r '.surface_id' <<<"$evidence")"
      rel_path="$(jq -r '.path' <<<"$evidence")"
      abs_path="${root_dir}/${rel_path}"

      if path_contains_all_fragments "$abs_path" "$evidence"; then
        record_pass "composition=${composition_id} surface=${surface_id} kind=required_evidence path=${rel_path}"
      elif claim_declares_fallback_for_surface "$claim" "$surface_id"; then
        record_pass "composition=${composition_id} surface=${surface_id} kind=required_evidence disposition=declared_fallback path=${rel_path}"
      else
        record_failure "composition=${composition_id} surface=${surface_id} kind=missing_child_surface path=${rel_path}"
      fi
    done < <(jq -c '.drift_checks.required_parent_evidence[]' <<<"$claim")

    while IFS= read -r mode_json; do
      mode_id="$(jq -r '.mode_id' <<<"$mode_json")"
      rel_path="$(jq -r '.path' <<<"$mode_json")"
      abs_path="${root_dir}/${rel_path}"
      allowed_surface="$(jq -r '.allowed_only_when_fallback_declared_for // empty' <<<"$mode_json")"

      if path_contains_all_fragments "$abs_path" "$mode_json"; then
        if [[ -n "$allowed_surface" ]] && claim_declares_fallback_for_surface "$claim" "$allowed_surface"; then
          record_pass "composition=${composition_id} mode=${mode_id} kind=proxy_bypass disposition=declared_fallback path=${rel_path}"
        else
          record_failure "composition=${composition_id} mode=${mode_id} kind=proxy_bypass_detected path=${rel_path}"
        fi
      else
        record_pass "composition=${composition_id} mode=${mode_id} kind=proxy_bypass_absent path=${rel_path}"
      fi
    done < <(jq -c '.drift_checks.proxy_bypass_modes[]?' <<<"$claim")
  done < <(jq -c '.claims[]' <<<"$contract_json")

  if (( validation_failures > 0 )); then
    return 1
  fi
}

run_selftest() {
  local truthful_root
  local bypass_root
  local truthful_contract
  local bypass_contract
  local truthful_output
  local bypass_output

  truthful_root="$(mktemp -d "${TMPDIR:-/tmp}/rgc_module_composition_truthful.XXXXXX")"
  truthful_contract="${truthful_root}/truthful.json"
  mkdir -p "${truthful_root}/src"
  cat >"${truthful_root}/src/truthful.rs" <<'EOF'
fn composed_parent() {
    novelty_scoring_contract::score_batch();
    novelty_synthesis_engine::publish_receipt();
    dark_matter_saturation_gate::consume_receipt();
}
EOF
  cat >"${truthful_contract}" <<'EOF'
{
  "schema_version": "franken-engine.module-composition-claim-ledger.v1",
  "claims": [
    {
      "composition_id": "truthful_parent",
      "allowed_provisional_fallbacks": [],
      "drift_checks": {
        "required_parent_evidence": [
          {
            "surface_id": "dark_matter_saturation_gate",
            "path": "src/truthful.rs",
            "fragments": [
              "dark_matter_saturation_gate::consume_receipt();"
            ]
          },
          {
            "surface_id": "novelty_scoring_contract",
            "path": "src/truthful.rs",
            "fragments": [
              "novelty_scoring_contract::score_batch();"
            ]
          },
          {
            "surface_id": "novelty_synthesis_engine",
            "path": "src/truthful.rs",
            "fragments": [
              "novelty_synthesis_engine::publish_receipt();"
            ]
          }
        ],
        "proxy_bypass_modes": []
      }
    }
  ]
}
EOF

  if ! truthful_output="$(run_drift_check "${truthful_contract}" "${truthful_root}" 2>&1)"; then
    record_failure "selftest truthful case unexpectedly failed"
    printf '%s\n' "$truthful_output" >&2
    return 1
  fi
  record_pass "selftest truthful composed module passes"

  bypass_root="$(mktemp -d "${TMPDIR:-/tmp}/rgc_module_composition_bypass.XXXXXX")"
  bypass_contract="${bypass_root}/bypass.json"
  mkdir -p "${bypass_root}/src"
  cat >"${bypass_root}/src/bypass.rs" <<'EOF'
fn bypass_parent(candidate: Candidate) {
    let score = candidate.description_length_bits;
    let promotion_rate = score / 2;
    if promotion_rate > 700_000 {
        dark_matter_saturation_gate::shadow_board_state();
    }
}
EOF
  cat >"${bypass_contract}" <<'EOF'
{
  "schema_version": "franken-engine.module-composition-claim-ledger.v1",
  "claims": [
    {
      "composition_id": "bypass_parent",
      "allowed_provisional_fallbacks": [],
      "drift_checks": {
        "required_parent_evidence": [
          {
            "surface_id": "dark_matter_saturation_gate",
            "path": "src/bypass.rs",
            "fragments": [
              "dark_matter_saturation_gate::consume_receipt();"
            ]
          },
          {
            "surface_id": "novelty_scoring_contract",
            "path": "src/bypass.rs",
            "fragments": [
              "novelty_scoring_contract::score_batch();"
            ]
          }
        ],
        "proxy_bypass_modes": [
          {
            "mode_id": "description_length_bits_proxy",
            "path": "src/bypass.rs",
            "fragments": [
              "candidate.description_length_bits"
            ]
          }
        ]
      }
    }
  ]
}
EOF

  if bypass_output="$(run_drift_check "${bypass_contract}" "${bypass_root}" 2>&1)"; then
    record_failure "selftest bypass case unexpectedly passed"
    return 1
  fi
  if [[ "${bypass_output}" != *"surface=novelty_scoring_contract kind=missing_child_surface"* ]]; then
    record_failure "selftest bypass case missing child-surface diagnostic"
    printf '%s\n' "${bypass_output}" >&2
    return 1
  fi
  if [[ "${bypass_output}" != *"mode=description_length_bits_proxy kind=proxy_bypass_detected"* ]]; then
    record_failure "selftest bypass case missing proxy-bypass diagnostic"
    printf '%s\n' "${bypass_output}" >&2
    return 1
  fi
  record_pass "selftest bypass module emits deterministic diagnostics"
}

mode="${1:-check}"
contract_path="${2:-${RGC_MODULE_COMPOSITION_CLAIM_LEDGER_PATH:-${default_contract}}}"
root_dir="${RGC_MODULE_COMPOSITION_ROOT_DIR:-${default_root_dir}}"

case "${mode}" in
  check)
    run_drift_check "${contract_path}" "${root_dir}"
    ;;
  selftest)
    run_drift_check "${contract_path}" "${root_dir}"
    run_selftest
    ;;
  *)
    echo "usage: $0 [check|selftest] [contract_path]" >&2
    exit 64
    ;;
esac

if (( validation_failures > 0 )); then
  exit 1
fi
