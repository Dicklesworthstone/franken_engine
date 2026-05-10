#!/usr/bin/env bash
set -euo pipefail

root_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
ledger_script="${root_dir}/scripts/rch_sync_closure_hotspot_ledger.sh"
docs_path="${root_dir}/docs/RCH_SYNC_CLOSURE_HOTSPOT_LEDGER.md"
golden_dir="${RCH_SYNC_CLOSURE_HOTSPOT_LEDGER_GOLDEN_DIR:-${root_dir}/scripts/testdata/goldens}"

record_pass() {
  printf 'PASS rch-sync-closure-hotspot-ledger %s\n' "$1"
}

record_failure() {
  printf 'FAIL rch-sync-closure-hotspot-ledger %s\n' "$1" >&2
}

golden_case_names() {
  cat <<'EOF'
repeated-full-sync
narrow-single-crate
missing-transfer-log
stable-hash-baseline
stable-hash-reordered
EOF
}

write_manifest() {
  local path="$1"
  local suite_id="$2"

  jq -n \
    --arg suite_id "$suite_id" '
    {
      schema_version: "franken-engine.remote-proof-suite-manifest.v1",
      suite_id: $suite_id,
      commands: [
        {
          command_id: "cmd-full-1",
          bead_id: "bd-vnkan",
          worker_id: "vmi1156319",
          requested_command: "rch exec -- env CARGO_TARGET_DIR=/tmp/rch_target_franken_engine_bd_vnkan_a cargo test -p frankenengine-engine --test semantic_dark_matter_engine_integration"
        },
        {
          command_id: "cmd-full-2",
          bead_id: "bd-vnkan",
          worker_id: "vmi1167313",
          requested_command: "rch exec -- env CARGO_TARGET_DIR=/tmp/rch_target_franken_engine_bd_vnkan_b cargo test -p frankenengine-engine --test semantic_dark_matter_engine_integration"
        },
        {
          command_id: "cmd-narrow-1",
          bead_id: "bd-vnkan",
          worker_id: "ts2",
          requested_command: "rch exec -- env CARGO_TARGET_DIR=/tmp/rch_target_franken_engine_bd_vnkan_c cargo test -p frankenengine-engine --test novelty_scoring_contract_integration"
        }
      ]
    }
  ' >"$path"
}

write_repeated_full_sync_log() {
  local path="$1"

  jq -nc '
    {
      suite_id: "semantic-dark-matter-pipeline",
      command_id: "cmd-full-1",
      worker_id: "vmi1156319",
      transfer_bytes: 470000,
      closure_roots: [
        range(1;48)
        | (
            "closure/root-"
            + (
                if . < 10 then
                  "0" + tostring
                else
                  tostring
                end
              )
          )
      ]
    }
  ' >"$path"
  jq -nc '
    {
      suite_id: "semantic-dark-matter-pipeline",
      command_id: "cmd-full-2",
      worker_id: "vmi1167313",
      transfer_bytes: 470000,
      closure_roots: [
        range(47;0;-1)
        | (
            "closure/root-"
            + (
                if . < 10 then
                  "0" + tostring
                else
                  tostring
                end
              )
          )
      ]
    }
  ' >>"$path"
}

write_reordered_full_sync_log() {
  local path="$1"

  jq -nc '
    {
      suite_id: "semantic-dark-matter-pipeline",
      command_id: "cmd-full-2",
      worker_id: "vmi1167313",
      transfer_bytes: 470000,
      closure_roots: [
        range(47;0;-1)
        | (
            "closure/root-"
            + (
                if . < 10 then
                  "0" + tostring
                else
                  tostring
                end
              )
          )
      ]
    }
  ' >"$path"
  jq -nc '
    {
      suite_id: "semantic-dark-matter-pipeline",
      command_id: "cmd-full-1",
      worker_id: "vmi1156319",
      transfer_bytes: 470000,
      closure_roots: [
        range(1;48)
        | (
            "closure/root-"
            + (
                if . < 10 then
                  "0" + tostring
                else
                  tostring
                end
              )
          )
      ]
    }
  ' >>"$path"
}

write_narrow_log() {
  local path="$1"

  jq -nc '
    {
      suite_id: "semantic-dark-matter-pipeline",
      command_id: "cmd-narrow-1",
      worker_id: "ts2",
      transfer_bytes: 2048,
      closure_roots: ["crates/franken-engine/src/novelty_scoring_contract.rs"]
    }
  ' >"$path"
}

run_check() {
  bash -n "$ledger_script"
  bash -n "${BASH_SOURCE[0]}"
  test -f "$docs_path"
  goldens_shape_ok
  record_pass "bash syntax and docs exist"
}

canonicalize_ledger() {
  local ledger_path="$1"
  local tmp_root="$2"

  jq --arg tmp_root "$tmp_root" '
    def scrub:
      if type == "string" then
        gsub($tmp_root; "[SMOKE_ROOT]")
        | gsub("/tmp/rch_target_"; "[RCH_TARGET]/")
        | gsub("/tmp/[A-Za-z0-9._-]+"; "[TMP_PATH]")
        | gsub("/data/tmp/[A-Za-z0-9._-]+"; "[DATA_TMP_PATH]")
      elif type == "array" then
        map(scrub)
      elif type == "object" then
        with_entries(.value |= scrub)
      else
        .
      end;
    scrub
  ' "$ledger_path"
}

assert_case_golden() {
  local case_name="$1"
  local ledger_path="$2"
  local tmp_root="$3"
  local golden_path="${golden_dir}/rch_sync_closure_hotspot_ledger_${case_name}.golden"

  if [[ "${UPDATE_GOLDENS:-0}" == "1" ]]; then
    mkdir -p "$golden_dir"
    canonicalize_ledger "$ledger_path" "$tmp_root" >"$golden_path"
    return 0
  fi

  if [[ ! -f "$golden_path" ]]; then
    record_failure "${case_name} missing golden"
    return 1
  fi

  if ! diff -u "$golden_path" <(canonicalize_ledger "$ledger_path" "$tmp_root"); then
    record_failure "${case_name} golden drift"
    return 1
  fi
}

goldens_shape_ok() {
  local missing=0
  local case_name golden_path

  if [[ "${UPDATE_GOLDENS:-0}" == "1" ]]; then
    return 0
  fi

  while IFS= read -r case_name; do
    golden_path="${golden_dir}/rch_sync_closure_hotspot_ledger_${case_name}.golden"
    if [[ ! -f "$golden_path" ]]; then
      record_failure "${case_name} missing checked-in golden"
      missing=1
      continue
    fi
    jq empty "$golden_path" >/dev/null || {
      record_failure "${case_name} invalid golden json"
      missing=1
    }
  done < <(golden_case_names)

  [[ "$missing" -eq 0 ]]
}

run_case() {
  local case_name="$1"
  local output_dir="$2"
  local tmp_root="$3"
  shift 3

  "$ledger_script" --output-dir "$output_dir" "$@" >/dev/null
  test -s "${output_dir}/sync_closure_hotspots.json"
  test -s "${output_dir}/sync_closure_summary.md"
  test -s "${output_dir}/commands.txt"
  test -s "${output_dir}/events.jsonl"
  assert_case_golden "$case_name" "${output_dir}/sync_closure_hotspots.json" "$tmp_root"
  record_pass "$case_name"
}

run_selftest() {
  local tmp_parent tmp_root fixture_dir case_dir

  run_check
  tmp_parent="${RCH_SYNC_CLOSURE_HOTSPOT_LEDGER_SMOKE_ARTIFACT_ROOT:-${TMPDIR:-/tmp}}"
  mkdir -p "$tmp_parent"
  tmp_root="$(mktemp -d "${tmp_parent%/}/rch-sync-closure-hotspot-ledger.XXXXXX")"
  fixture_dir="${tmp_root}/fixtures"
  mkdir -p "$fixture_dir"

  write_manifest "${fixture_dir}/suite_manifest.json" "semantic-dark-matter-pipeline"
  write_repeated_full_sync_log "${fixture_dir}/full_sync.jsonl"
  write_reordered_full_sync_log "${fixture_dir}/full_sync_reordered.jsonl"
  write_narrow_log "${fixture_dir}/narrow.jsonl"

  case_dir="${tmp_root}/repeated-full-sync"
  run_case "repeated-full-sync" "$case_dir" "$tmp_root" \
    --suite-manifest-json "${fixture_dir}/suite_manifest.json" \
    --transfer-log-jsonl "${fixture_dir}/full_sync.jsonl"
  jq -e '
    .analysis_status == "ok"
    and .transfer_log_status == "provided"
    and .logged_command_count == 2
    and .total_full_sync_commands == 2
    and .total_narrow_sync_commands == 0
    and .total_unique_roots == 47
    and .repeated_hotspot_count == 47
    and (.hotspots[0].occurrence_count == 2)
    and (.hotspots[0].full_sync_hits == 2)
    and (.hash_basis.input_hash | length == 64)
    and (.hash_basis.ledger_hash | length == 64)
  ' "${case_dir}/sync_closure_hotspots.json" >/dev/null
  record_pass "repeated full-sync assertions"

  case_dir="${tmp_root}/narrow-single-crate"
  run_case "narrow-single-crate" "$case_dir" "$tmp_root" \
    --suite-manifest-json "${fixture_dir}/suite_manifest.json" \
    --transfer-log-jsonl "${fixture_dir}/narrow.jsonl"
  jq -e '
    .analysis_status == "ok"
    and .logged_command_count == 1
    and .total_full_sync_commands == 0
    and .total_narrow_sync_commands == 1
    and .total_unique_roots == 1
    and .repeated_hotspot_count == 0
    and (.hotspots[0].root == "crates/franken-engine/src/novelty_scoring_contract.rs")
    and (.hotspots[0].narrow_sync_hits == 1)
  ' "${case_dir}/sync_closure_hotspots.json" >/dev/null
  record_pass "narrow single-crate assertions"

  case_dir="${tmp_root}/missing-transfer-log"
  run_case "missing-transfer-log" "$case_dir" "$tmp_root" \
    --suite-manifest-json "${fixture_dir}/suite_manifest.json"
  jq -e '
    .analysis_status == "degraded"
    and .degradation_reason == "missing_transfer_log"
    and .transfer_log_status == "missing"
    and .logged_command_count == 0
    and .total_unique_roots == 0
    and (.unobserved_command_ids | length == 3)
  ' "${case_dir}/sync_closure_hotspots.json" >/dev/null
  record_pass "missing transfer-log degraded assertions"

  run_case "stable-hash-baseline" "${tmp_root}/stable-hash-a" "$tmp_root" \
    --suite-manifest-json "${fixture_dir}/suite_manifest.json" \
    --transfer-log-jsonl "${fixture_dir}/full_sync.jsonl"
  run_case "stable-hash-reordered" "${tmp_root}/stable-hash-b" "$tmp_root" \
    --suite-manifest-json "${fixture_dir}/suite_manifest.json" \
    --transfer-log-jsonl "${fixture_dir}/full_sync_reordered.jsonl"
  test "$(jq -r '.hash_basis.input_hash' "${tmp_root}/stable-hash-a/sync_closure_hotspots.json")" = \
    "$(jq -r '.hash_basis.input_hash' "${tmp_root}/stable-hash-b/sync_closure_hotspots.json")"
  test "$(jq -r '.hash_basis.ledger_hash' "${tmp_root}/stable-hash-a/sync_closure_hotspots.json")" = \
    "$(jq -r '.hash_basis.ledger_hash' "${tmp_root}/stable-hash-b/sync_closure_hotspots.json")"
  test "$(jq -cS '{analysis_status, transfer_log_status, total_unique_roots, repeated_hotspot_count, hotspots, command_summaries}' "${tmp_root}/stable-hash-a/sync_closure_hotspots.json")" = \
    "$(jq -cS '{analysis_status, transfer_log_status, total_unique_roots, repeated_hotspot_count, hotspots, command_summaries}' "${tmp_root}/stable-hash-b/sync_closure_hotspots.json")"
  record_pass "deterministic ordering and stable hashes"

  printf 'rch_sync_closure_hotspot_ledger_smoke_artifacts=%s\n' "$tmp_root"
}

case "${1:-check}" in
  check)
    run_check
    ;;
  selftest)
    run_selftest
    ;;
  *)
    record_failure "unknown mode: ${1:-}"
    exit 64
    ;;
esac
