#!/usr/bin/env bash
set -euo pipefail

root_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
script_path="${root_dir}/scripts/swarm_proof_command_preflight.sh"
contract_path="${root_dir}/docs/swarm_proof_command_preflight_contract_v1.json"
docs_path="${root_dir}/docs/SWARM_PROOF_COMMAND_PREFLIGHT.md"
cases_path="${root_dir}/scripts/testdata/swarm_proof_command_preflight/cases.json"
mode="${1:-check}"
output_root="${2:-${SWARM_PROOF_COMMAND_PREFLIGHT_SMOKE_DIR:-${TMPDIR:-/tmp}/franken-engine-proof-command-preflight-smoke-$$}}"
failures=0

record_pass() {
  printf 'PASS swarm-proof-command-preflight %s\n' "$1"
}

record_failure() {
  printf 'FAIL swarm-proof-command-preflight %s\n' "$1" >&2
  failures=$((failures + 1))
}

usage() {
  cat >&2 <<'EOF'
Usage: ./scripts/e2e/swarm_proof_command_preflight_smoke.sh [check|selftest] [output_root]
EOF
}

contract_shape_ok() {
  local candidate_contract="${1:-$contract_path}"

  jq -e '
    def shellish_tokens:
      gsub("\\\\ "; " ")
      | split(" ")
      | map(gsub("^[\\u0027\\\"]+|[\\u0027\\\"]+$"; ""));
    def has_effective_linker_policy:
      shellish_tokens as $tokens
      | [
          range(0; ($tokens | length)) as $index
          | if ($tokens[$index] == "-Clinker-features=-lld"
                or $tokens[$index] == "RUSTFLAGS=-Clinker-features=-lld") then
              "disabled"
            elif ($tokens[$index] | startswith("-Clinker-features="))
                 or ($tokens[$index] | startswith("RUSTFLAGS=-Clinker-features=")) then
              "other"
            elif ($tokens[$index] == "-C" or $tokens[$index] == "RUSTFLAGS=-C")
                 and ($tokens[$index + 1] // "" | startswith("linker-features=")) then
              if $tokens[$index + 1] == "linker-features=-lld" then "disabled" else "other" end
            else
              empty
            end
        ]
      | last == "disabled";
    def rustflags_composed:
      (contains("RUSTFLAGS=") | not) or has_effective_linker_policy;
    .schema_version == "franken-engine.swarm-proof-command-preflight-contract.v1"
    and .bead_id == "bd-ua5n2.9"
    and (.depends_on | index("bd-ua5n2.1") != null)
    and .heavy_command_policy.cargo_requires_rch_exec == true
    and .heavy_command_policy.accepted_heavy_prefix == "env -u CARGO_ENCODED_RUSTFLAGS rch exec -- env -u CARGO_ENCODED_RUSTFLAGS"
    and .heavy_command_policy.cargo_encoded_rustflags_clear.client_required == true
    and .heavy_command_policy.cargo_encoded_rustflags_clear.remote_required == true
    and .heavy_command_policy.cargo_encoded_rustflags_clear.assignment_supported == false
    and .heavy_command_policy.target_dir_required == true
    and .heavy_command_policy.linker_policy_source == ".cargo/config.toml"
    and .heavy_command_policy.rustflags_override.default == "omit and inherit the checked-in linker policy"
    and .heavy_command_policy.rustflags_override.required_token_when_present == "-Clinker-features=-lld"
    and .heavy_command_policy.rustflags_override.accepted_exact_token_sequences == [["-Clinker-features=-lld"], ["-C", "linker-features=-lld"]]
    and .heavy_command_policy.rustflags_override.matching_semantics == "Exact whitespace-delimited tokens after simple quote and backslash decoding; embedded substrings do not satisfy the policy."
    and .heavy_command_policy.rustflags_override.cargo_encoded_rustflags_supported == false
    and .heavy_command_policy.rustflags_override.cache_identity_when_present == true
    and .heavy_command_policy.shell_wrappers_allowed == false
    and .heavy_command_policy.bare_cargo_allowed == false
    and (.accepted_env_allowlist | index("CARGO_TARGET_DIR") != null)
    and (.accepted_env_allowlist | index("RCH_VISIBILITY") != null)
    and (.accepted_env_allowlist | index("RUSTFLAGS") != null)
    and (.accepted_env_allowlist | index("CARGO_ENCODED_RUSTFLAGS") == null)
    and (.valid_decisions | sort) == ["needs_human_review", "non_heavy_read_only", "proof_safe", "proof_unsafe"]
    and (.fixture_cases | length) == 14
    and (.valid_reason_codes | index("target_dir_bead_mismatch") != null)
    and (.valid_reason_codes | index("uncomposed_rustflags_override") != null)
    and (.valid_reason_codes | index("missing_encoded_rustflags_clear") != null)
    and (.valid_reason_codes | index("unsupported_env_syntax") != null)
    and (.warm_target_command_matrix | length) == 6
    and all(.warm_target_command_matrix[]; has("class") and has("canonical_command_shape") and has("required_env") and has("target_dir_template") and has("reuse_safety_constraints") and has("stale_cache_invalidation_inputs") and has("prefer_narrower_proof_when") and has("examples"))
    and all(.warm_target_command_matrix[];
      .class == "source_only"
      or (.canonical_command_shape | startswith("env -u CARGO_ENCODED_RUSTFLAGS rch exec -- env -u CARGO_ENCODED_RUSTFLAGS")))
    and all(.warm_target_command_matrix[] | select(.class != "source_only");
      all(.examples[];
        (.command | startswith("env -u CARGO_ENCODED_RUSTFLAGS rch exec -- env -u CARGO_ENCODED_RUSTFLAGS"))))
    and all(.warm_target_command_matrix[] | select(.class != "source_only"); (.target_dir_template | contains("<safe_bead_id>")))
    and all(.warm_target_command_matrix[] | select(.class != "source_only"); (.required_env | index("RUSTFLAGS")) == null)
    and all(.warm_target_command_matrix[] | select(.class != "source_only"); (.stale_cache_invalidation_inputs | index("RUSTFLAGS")) != null)
    and all(.warm_target_command_matrix[] | select(.class != "source_only");
      (.canonical_command_shape | rustflags_composed)
      and all(.examples[]; (.command | rustflags_composed)))
    and any(.warm_target_command_matrix[]; .class == "focused_lib_test" and any(.examples[]; .bead_id == "bd-7eefz"))
    and any(.warm_target_command_matrix[]; .class == "package_all_targets" and any(.examples[]; .bead_id == "bd-zy517"))
    and .mutation_policy.runs_cargo == false
    and .mutation_policy.runs_rch == false
    and .mutation_policy.mutates_br == false
  ' "$candidate_contract" >/dev/null
}

docs_shape_ok() {
  grep -Fq 'never executes the command under inspection' "$docs_path" \
    && grep -Fq 'shell-wrapped Cargo or RCH commands' "$docs_path" \
    && grep -Fq 'bare local Cargo' "$docs_path" \
    && grep -Fq 'unsupported env leakage' "$docs_path" \
    && grep -Fq 'RCH_VISIBILITY' "$docs_path" \
    && grep -Fq '.cargo/config.toml' "$docs_path" \
    && grep -Fq -- '-Clinker-features=-lld' "$docs_path" \
    && grep -Fq 'linker-only override' "$docs_path" \
    && grep -Fq -- '-Cmetadata=-Clinker-features=-lld' "$docs_path" \
    && grep -Fq 'CARGO_ENCODED_RUSTFLAGS' "$docs_path" \
    && grep -Fq 'client and worker' "$docs_path" \
    && grep -Fq '/tmp/rch_target_franken_engine_<safe_bead_id>' "$docs_path"
}

fixtures_shape_ok() {
  jq -e '
    .schema_version == "franken-engine.swarm-proof-command-preflight-fixtures.v1"
    and .contract_schema_version == "franken-engine.swarm-proof-command-preflight-contract.v1"
    and (.cases | length) == 22
    and all(.cases[]; has("case_id") and has("command") and has("context") and has("expected"))
    and ([.cases[].expected.decision] | unique | sort) == ["needs_human_review", "non_heavy_read_only", "proof_safe", "proof_unsafe"]
    and ([.cases[].expected.reason_code] | unique | sort) == [
      "bare_cargo_not_allowed",
      "direct_rch_cargo_proof",
      "missing_encoded_rustflags_clear",
      "missing_rch_visibility",
      "missing_target_dir_policy",
      "non_heavy_read_only",
      "shell_wrapper_fallback_risk",
      "target_dir_bead_mismatch",
      "uncomposed_rustflags_override",
      "unknown_command_shape",
      "unsupported_env_leakage",
      "unsupported_env_syntax"
    ]
    and any(.cases[]; .case_id == "accepted_composed_rustflags" and .expected.decision == "proof_safe")
    and any(.cases[]; .case_id == "accepted_two_token_linker_policy" and .expected.decision == "proof_safe")
    and any(.cases[]; .case_id == "rejected_uncomposed_rustflags" and .expected.reason_code == "uncomposed_rustflags_override")
    and any(.cases[]; .case_id == "rejected_rustflags_substring_bypass" and .expected.reason_code == "uncomposed_rustflags_override")
    and any(.cases[]; .case_id == "rejected_encoded_rustflags" and .expected.reason_code == "unsupported_env_leakage")
    and any(.cases[]; .case_id == "rejected_later_linker_feature_reenable" and .expected.reason_code == "uncomposed_rustflags_override")
    and any(.cases[]; .case_id == "rejected_missing_client_encoded_clear" and .expected.reason_code == "missing_encoded_rustflags_clear")
    and any(.cases[]; .case_id == "rejected_missing_remote_encoded_clear" and .expected.reason_code == "missing_encoded_rustflags_clear")
    and any(.cases[]; .case_id == "rejected_remote_env_option" and .expected.reason_code == "unsupported_env_syntax")
    and any(.cases[]; .case_id == "rejected_target_dir_suffix_decoy" and .expected.reason_code == "missing_target_dir_policy")
    and any(.cases[]; .case_id == "rejected_visibility_suffix_decoy" and .expected.reason_code == "missing_rch_visibility")
    and any(.cases[]; .case_id == "rejected_empty_visibility" and .expected.reason_code == "missing_rch_visibility")
    and any(.cases[]; .case_id == "rejected_shell_expansion_in_target_dir" and .expected.reason_code == "unsupported_env_syntax")
    and all(.cases[]; (.expected.remediation | length) >= 40)
  ' "$cases_path" >/dev/null
}

script_static_ok() {
  bash -n "$script_path"
  bash -n "${BASH_SOURCE[0]}"
  if command -v shellcheck >/dev/null 2>&1; then
    shellcheck -x "$script_path" "${BASH_SOURCE[0]}"
  fi
}

assert_case_output() {
  local case_json="$1"
  local output_dir="$2"
  local preflight_path="${output_dir}/preflight_report.json"
  local manifest_path="${output_dir}/run_manifest.json"
  local case_id

  case_id="$(jq -r '.case_id' <<<"$case_json")"
  jq empty "$preflight_path" "$manifest_path" >/dev/null
  test -s "${output_dir}/events.jsonl"
  test -s "${output_dir}/commands.txt"
  test -s "${output_dir}/report.md"

  jq -e \
    --argjson expected "$(jq '.expected' <<<"$case_json")" \
    --arg case_id "$case_id" '
      .schema_version == "franken-engine.swarm-proof-command-preflight.v1"
      and .case_id == $case_id
      and .decision == $expected.decision
      and .reason_code == $expected.reason_code
      and .command.command_kind == $expected.command_kind
      and .command.transport == $expected.transport
      and (if $expected.reason_code == "target_dir_bead_mismatch" then .command.target_dir_correlates_with_bead == false else true end)
      and (if $expected.reason_code == "direct_rch_cargo_proof" then .command.target_dir_correlates_with_bead == true else true end)
      and (if $expected.reason_code == "direct_rch_cargo_proof" then
        .command.client_encoded_rustflags_cleared == true
        and .command.remote_encoded_rustflags_cleared == true
      else true end)
      and (if $expected.reason_code == "missing_encoded_rustflags_clear" then
        (.command.client_encoded_rustflags_cleared and .command.remote_encoded_rustflags_cleared) == false
      else true end)
      and (if ($case_id == "accepted_composed_rustflags" or $case_id == "accepted_two_token_linker_policy") then
        .command.has_rustflags_override == true and .command.rustflags_linker_policy_composed == true
      else true end)
      and (if $expected.reason_code == "uncomposed_rustflags_override" then
        .command.has_rustflags_override == true and .command.rustflags_linker_policy_composed == false
      else true end)
      and (if $expected.reason_code == "unsupported_env_syntax" then
        .command.env_prefix_parse_ok == false
      else .command.env_prefix_parse_ok == true end)
      and .remediation == $expected.remediation
      and .pasteable_command == $expected.pasteable_command
      and .non_mutation_attestation.runs_cargo == false
      and .non_mutation_attestation.runs_rch == false
      and .non_mutation_attestation.mutates_br == false
    ' "$preflight_path" >/dev/null || record_failure "${case_id} preflight output mismatch"
}

run_case() {
  local case_json="$1"
  local tmp_root="$2"
  local case_id case_dir input_path expected_exit actual_exit

  case_id="$(jq -r '.case_id' <<<"$case_json")"
  case_dir="${tmp_root}/${case_id}"
  input_path="${case_dir}/input.json"
  mkdir -p "$case_dir"
  jq '.' <<<"$case_json" >"$input_path"

  expected_exit="$(jq -r '.expected.exit_code' <<<"$case_json")"
  set +e
  "$script_path" --command-json "$input_path" --output-dir "${case_dir}/out" >/dev/null 2>&1
  actual_exit=$?
  set -e

  if [[ "$actual_exit" -ne "$expected_exit" ]]; then
    record_failure "${case_id} exit ${actual_exit}, expected ${expected_exit}"
    return
  fi

  assert_case_output "$case_json" "${case_dir}/out"
  record_pass "$case_id"
}

run_check() {
  jq empty "$contract_path" "$cases_path" >/dev/null
  script_static_ok
  contract_shape_ok || record_failure "contract shape"
  docs_shape_ok || record_failure "docs shape"
  fixtures_shape_ok || record_failure "fixture shape"

  if [[ "$failures" -eq 0 ]]; then
    record_pass "check"
  fi
}

# linker-policy-negative-fixtures-begin: contract mutation probes
run_linker_policy_selftest() {
  local tmp_root="$1"
  local bad_linker_only="${tmp_root}/bad-linker-only-contract.json"
  local bad_uncomposed="${tmp_root}/bad-uncomposed-contract.json"
  local bad_substring="${tmp_root}/bad-substring-contract.json"
  local bad_later_reenable="${tmp_root}/bad-later-reenable-contract.json"
  local bad_client_clear="${tmp_root}/bad-client-clear-contract.json"
  local bad_remote_clear="${tmp_root}/bad-remote-clear-contract.json"
  local good_composed="${tmp_root}/good-composed-contract.json"
  local good_two_token="${tmp_root}/good-two-token-contract.json"

  mkdir -p "$tmp_root"
  jq '(.warm_target_command_matrix[] | select(.class == "focused_lib_test") | .canonical_command_shape) |= sub("CARGO_BUILD_JOBS=1"; "RUSTFLAGS=-Clinker=cc CARGO_BUILD_JOBS=1")' \
    "$contract_path" >"$bad_linker_only"
  if contract_shape_ok "$bad_linker_only" >/dev/null 2>&1; then
    record_failure "selftest accepted linker-only canonical RUSTFLAGS override"
  else
    record_pass "selftest rejects linker-only canonical RUSTFLAGS override"
  fi

  jq '(.warm_target_command_matrix[] | select(.class == "focused_lib_test") | .canonical_command_shape) |= sub("CARGO_BUILD_JOBS=1"; "RUSTFLAGS=-Cdebuginfo=0 CARGO_BUILD_JOBS=1")' \
    "$contract_path" >"$bad_uncomposed"
  if contract_shape_ok "$bad_uncomposed" >/dev/null 2>&1; then
    record_failure "selftest accepted uncomposed canonical RUSTFLAGS override"
  else
    record_pass "selftest rejects uncomposed canonical RUSTFLAGS override"
  fi

  jq '(.warm_target_command_matrix[] | select(.class == "focused_lib_test") | .canonical_command_shape) |= sub("CARGO_BUILD_JOBS=1"; "RUSTFLAGS=-Cmetadata=-Clinker-features=-lld CARGO_BUILD_JOBS=1")' \
    "$contract_path" >"$bad_substring"
  if contract_shape_ok "$bad_substring" >/dev/null 2>&1; then
    record_failure "selftest accepted RUSTFLAGS substring bypass"
  else
    record_pass "selftest rejects RUSTFLAGS substring bypass"
  fi

  jq '(.warm_target_command_matrix[] | select(.class == "focused_lib_test") | .canonical_command_shape) |= sub("CARGO_BUILD_JOBS=1"; "RUSTFLAGS=-Clinker-features=-lld\\ -Clinker-features=+lld CARGO_BUILD_JOBS=1")' \
    "$contract_path" >"$bad_later_reenable"
  if contract_shape_ok "$bad_later_reenable" >/dev/null 2>&1; then
    record_failure "selftest accepted later linker-feature re-enable"
  else
    record_pass "selftest rejects later linker-feature re-enable"
  fi

  jq '(.warm_target_command_matrix[] | select(.class == "focused_lib_test") | .canonical_command_shape) |= sub("^env -u CARGO_ENCODED_RUSTFLAGS "; "")' \
    "$contract_path" >"$bad_client_clear"
  if contract_shape_ok "$bad_client_clear" >/dev/null 2>&1; then
    record_failure "selftest accepted missing client encoded-flag clear"
  else
    record_pass "selftest rejects missing client encoded-flag clear"
  fi

  jq '(.warm_target_command_matrix[] | select(.class == "focused_lib_test") | .canonical_command_shape) |= sub("rch exec -- env -u CARGO_ENCODED_RUSTFLAGS"; "rch exec -- env")' \
    "$contract_path" >"$bad_remote_clear"
  if contract_shape_ok "$bad_remote_clear" >/dev/null 2>&1; then
    record_failure "selftest accepted missing remote encoded-flag clear"
  else
    record_pass "selftest rejects missing remote encoded-flag clear"
  fi

  jq '(.warm_target_command_matrix[] | select(.class == "focused_lib_test") | .canonical_command_shape) |= sub("CARGO_BUILD_JOBS=1"; "RUSTFLAGS=-Cdebuginfo=0\\ -Clinker-features=-lld CARGO_BUILD_JOBS=1")' \
    "$contract_path" >"$good_composed"
  if contract_shape_ok "$good_composed" >/dev/null 2>&1; then
    record_pass "selftest accepts composed canonical RUSTFLAGS override"
  else
    record_failure "selftest rejected composed canonical RUSTFLAGS override"
  fi

  jq '(.warm_target_command_matrix[] | select(.class == "focused_lib_test") | .canonical_command_shape) |= sub("CARGO_BUILD_JOBS=1"; "RUSTFLAGS=-Cdebuginfo=0\\ -C\\ linker-features=-lld CARGO_BUILD_JOBS=1")' \
    "$contract_path" >"$good_two_token"
  if contract_shape_ok "$good_two_token" >/dev/null 2>&1; then
    record_pass "selftest accepts two-token linker policy"
  else
    record_failure "selftest rejected two-token linker policy"
  fi
}
# linker-policy-negative-fixtures-end

run_selftest() {
  local tmp_root="$1"

  run_check
  if [[ "$failures" -ne 0 ]]; then
    return
  fi

  run_linker_policy_selftest "${tmp_root}/linker-policy"
  if [[ "$failures" -ne 0 ]]; then
    return
  fi

  while IFS= read -r case_json; do
    run_case "$case_json" "$tmp_root"
  done < <(jq -c '.cases[]' "$cases_path")
}

case "$mode" in
  check)
    run_check
    ;;
  selftest)
    run_selftest "$output_root"
    ;;
  -h|--help|help)
    usage
    ;;
  *)
    usage
    record_failure "unknown mode: ${mode}"
    exit 64
    ;;
esac

if [[ "$failures" -ne 0 ]]; then
  exit 1
fi
