#!/usr/bin/env bash
set -euo pipefail

root_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
contract_path="${1:-${root_dir}/docs/rch_validation_closeout_templates_v1.json}"
doc_path="${root_dir}/docs/RCH_VALIDATION_CLOSEOUT_TEMPLATES_V1.md"

record_pass() {
  printf 'PASS rch-validation-closeout-templates %s\n' "$1"
}

record_failure() {
  printf 'FAIL rch-validation-closeout-templates %s\n' "$1" >&2
}

require_jq() {
  if ! command -v jq >/dev/null 2>&1; then
    echo "jq is required for rch validation closeout template smoke" >&2
    exit 2
  fi
}

validate_contract() {
  local path="$1"
  local missing_template_ids invalid_markers misleading_blockers missing_examples

  if ! jq -e '
    .schema_version == "franken-engine.rch-validation-closeout-templates.v1"
    and .bead_id == "bd-n04l9"
    and .parent_bead_id == "bd-zk8ji"
    and (.required_evidence_markers | length) == 7
    and (.templates | length) >= 5
  ' "$path" >/dev/null; then
    record_failure "schema header invalid: $path"
    return 1
  fi

  missing_template_ids="$(
    jq -r '
      [
        .templates[]
        | select(
            (
              has("template_id")
              and has("final_verdict")
              and has("reason_code")
              and has("source_evidence")
              and has("worker_id")
              and has("command")
              and has("target_dir")
              and has("component_toolchain")
              and has("next_action")
              and has("agent_mail_subject")
              and has("agent_mail_body_md")
              and has("br_close_reason")
            ) | not
          )
        | (.template_id // "<missing-template-id>")
      ]
      | join("\n")
    ' "$path"
  )"
  if [[ -n "$missing_template_ids" ]]; then
    record_failure "templates missing required fields"
    printf '%s\n' "$missing_template_ids" >&2
    return 1
  fi

  invalid_markers="$(
    jq -r '
      .required_evidence_markers as $markers
      | [
          .templates[]
          | . as $template
          | select(
              any($markers[]; . as $marker | (($template.agent_mail_body_md | contains($marker)) | not))
              or any($markers[]; . as $marker | (($template.br_close_reason | contains($marker)) | not))
            )
          | .template_id
        ]
      | join("\n")
    ' "$path"
  )"
  if [[ -n "$invalid_markers" ]]; then
    record_failure "templates missing evidence markers"
    printf '%s\n' "$invalid_markers" >&2
    return 1
  fi

  misleading_blockers="$(
    jq -r '
      [
        .templates[]
        | select(.source_evidence == false)
        | (.agent_mail_body_md + "\n" + .br_close_reason) as $text
        | select(
            ($text | contains("not source evidence") | not)
            or ($text | test("source evidence=true|source validation passed|validation passed"; "i"))
          )
        | .template_id
      ]
      | join("\n")
    ' "$path"
  )"
  if [[ -n "$misleading_blockers" ]]; then
    record_failure "blocker templates imply source success or omit not-source-evidence language"
    printf '%s\n' "$misleading_blockers" >&2
    return 1
  fi

  missing_examples="$(
    jq -r '
      [.templates[].template_id] as $ids
      | [
          "cargo-clippy-missing",
          "ssh-timeout-no-final-verdict",
          "full-cargo-test-timeout",
          "all-targets-check-pass",
          "source-diagnostic-failure"
        ] as $expected
      | [
          $expected[]
          | select(. as $id | $ids | index($id) | not)
        ]
      | join("\n")
    ' "$path"
  )"
  if [[ -n "$missing_examples" ]]; then
    record_failure "missing required examples"
    printf '%s\n' "$missing_examples" >&2
    return 1
  fi

  jq -e '
    (.templates[] | select(.template_id == "cargo-clippy-missing") | .component_toolchain | contains("cargo-clippy"))
    and (.templates[] | select(.template_id == "ssh-timeout-no-final-verdict") | .final_verdict == "transport_timeout")
    and (.templates[] | select(.template_id == "full-cargo-test-timeout") | .command | test("cargo test$"))
    and (.templates[] | select(.template_id == "all-targets-check-pass") | .source_evidence == true and .final_verdict == "source_pass")
    and (.templates[] | select(.template_id == "source-diagnostic-failure") | .source_evidence == true and .final_verdict == "source_failure")
  ' "$path" >/dev/null
}

validate_docs() {
  for text in \
    "Cargo-Clippy Missing" \
    "SSH Timeout" \
    "Full Cargo Test Timed Out" \
    "All-Targets Check Pass" \
    "Source Diagnostic Failure" \
    "command=rch exec --" \
    "not source evidence"; do
    if ! grep -Fq "$text" "$doc_path"; then
      record_failure "docs missing: $text"
      return 1
    fi
  done
}

assert_negative_fixture() {
  local tmp_parent tmp_path actual_exit

  tmp_parent="${RCH_VALIDATION_CLOSEOUT_TEMPLATE_SMOKE_ROOT:-${TMPDIR:-/tmp}}"
  mkdir -p "$tmp_parent"
  tmp_path="$(mktemp "${tmp_parent%/}/rch-validation-closeout-bad.XXXXXX.json")"

  jq '(.templates[0].agent_mail_body_md |= gsub("command=rch exec --"; "command="))' "$contract_path" >"$tmp_path"

  set +e
  validate_contract "$tmp_path" >/dev/null 2>&1
  actual_exit=$?
  set -e

  if [[ "$actual_exit" -eq 0 ]]; then
    record_failure "negative fixture without rch command marker passed"
    return 1
  fi

  record_pass "negative fixture rejects missing command marker"
}

main() {
  require_jq
  bash -n "${BASH_SOURCE[0]}"
  jq empty "$contract_path" >/dev/null
  validate_contract "$contract_path"
  validate_docs
  assert_negative_fixture
  record_pass "contract and docs"
}

main "$@"
