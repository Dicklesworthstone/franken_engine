#!/usr/bin/env bash
# BRIDGE-00.2 (bd-performance-conformance-bridge-tu32j.1.2)
# Public/CI Executable-Output, Conformance-Claim, and Claim-Language Truth Gate.
#
# Validates authoritative repository claim language and proves via a neutral
# producer-distinct challenge harness that backend labels, simulated compile
# durations, input-only hashes, stale/tampered bundles, unowned exclusions, and
# synthetic Test262 percentages fail closed with deterministic FE-OUTGATE-* codes.
set -euo pipefail

root_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$root_dir" || exit 2
# shellcheck source=scripts/lib/proof_artifact_contract.sh
source "${root_dir}/scripts/lib/proof_artifact_contract.sh"

mode="${1:-ci}"
case "$mode" in
  ci | check) ;;
  *)
    echo "usage: $0 [ci|check] [run_dir]" >&2
    exit 2
    ;;
esac

timestamp="$(date -u +%Y%m%dT%H%M%SZ)"
artifact_root="${EXECUTABLE_OUTPUT_TRUTH_GATE_ARTIFACT_ROOT:-artifacts/executable_output_truth_gate}"
run_dir="${2:-${artifact_root}/${timestamp}-$$}"
target_dir="${EXECUTABLE_OUTPUT_TRUTH_GATE_CARGO_TARGET_DIR:-${RCH_TARGET_BASE:-target2}/output_truth_gate_${timestamp}_$$}"
toolchain="${RUSTUP_TOOLCHAIN:-nightly-2026-09-21}"
tool_manifest="tools/execution-truth-ledger/Cargo.toml"
validator_bin="${EXECUTABLE_OUTPUT_TRUTH_VALIDATOR_BIN:-}"

mkdir -p "$(dirname "$run_dir")"
if [[ -e "$run_dir" ]]; then
  echo "refusing to overwrite existing run directory: ${run_dir}" >&2
  exit 2
fi
mkdir -p "$run_dir/logs"

commands_path="${run_dir}/commands.txt"
events_path="${run_dir}/events.jsonl"
audit_events_path="${run_dir}/audit_events.jsonl"
audit_report_path="${run_dir}/audit_report.json"
challenge_handoff_path="${run_dir}/challenge_handoff.json"
env_path="${run_dir}/env.json"
repro_lock_path="${run_dir}/repro.lock"
provenance_path="${run_dir}/provenance_graph.json"
legal_path="${run_dir}/LEGAL.md"
rollback_path="${run_dir}/ROLLBACK.md"
manifest_path="${run_dir}/run_manifest.json"
: >"$commands_path"
: >"$events_path"

run_id="run-output-truth-gate-${timestamp}-$$"
trace_id="trace-output-truth-gate-${timestamp}-$$"
seq_num=0
append_event() {
  local phase="$1" decision="$2" reason="$3"
  seq_num=$((seq_num + 1))
  jq -nc \
    --arg schema_version "franken-engine.executable-output-truth-gate.event.v1" \
    --arg run_id "$run_id" \
    --arg trace_id "$trace_id" \
    --arg phase "$phase" \
    --argjson sequence "$seq_num" \
    --arg decision "$decision" \
    --arg reason "$(proof_contract_redact_text "$reason" | cut -c1-768)" \
    '{
      schema_version: $schema_version,
      run_id: $run_id,
      trace_id: $trace_id,
      phase: $phase,
      sequence: $sequence,
      decision: $decision,
      reason: $reason
    }' >>"$events_path"
}

append_event "gate.start" "info" "mode=${mode} run_dir=${run_dir}"

if [[ -z "$validator_bin" || ! -x "$validator_bin" ]]; then
  validator_bin="${target_dir}/debug/franken_execution_truth_ledger"
  if command -v rch >/dev/null 2>&1 && [[ "${GITHUB_ACTIONS:-}" != "true" ]]; then
    printf 'RCH_TOPOLOGY_PATHS_PRESENT=1 rch exec -- env RUSTUP_TOOLCHAIN=%q CARGO_TARGET_DIR=%q cargo build --locked --manifest-path %q --bin franken_execution_truth_ledger\n' \
      "$toolchain" "$target_dir" "$tool_manifest" >>"$commands_path"
    RCH_TOPOLOGY_PATHS_PRESENT=1 rch exec -- env \
      RUSTUP_TOOLCHAIN="$toolchain" \
      CARGO_TARGET_DIR="$target_dir" \
      cargo build -j 2 --locked --manifest-path "$tool_manifest" \
      --bin franken_execution_truth_ledger >"${run_dir}/logs/build.log" 2>&1
  else
    printf 'CARGO_TARGET_DIR=%q cargo build --locked --manifest-path %q --bin franken_execution_truth_ledger\n' \
      "$target_dir" "$tool_manifest" >>"$commands_path"
    CARGO_TARGET_DIR="$target_dir" cargo build --locked --manifest-path "$tool_manifest" \
      --bin franken_execution_truth_ledger >"${run_dir}/logs/build.log" 2>&1
  fi
fi
append_event "gate.validator_ready" "pass" "validator=${validator_bin}"

if [[ "$mode" == "ci" ]]; then
  if command -v rch >/dev/null 2>&1 && [[ "${GITHUB_ACTIONS:-}" != "true" ]]; then
    printf 'RCH_TOPOLOGY_PATHS_PRESENT=1 rch exec -- env RUSTUP_TOOLCHAIN=%q CARGO_TARGET_DIR=%q cargo test --locked --manifest-path %q --test executable_output_truth_gate_tu32j_1_2\n' \
      "$toolchain" "$target_dir" "$tool_manifest" >>"$commands_path"
    RCH_TOPOLOGY_PATHS_PRESENT=1 rch exec -- env \
      RUSTUP_TOOLCHAIN="$toolchain" \
      CARGO_TARGET_DIR="$target_dir" \
      cargo test -j 2 --locked --manifest-path "$tool_manifest" \
      --test executable_output_truth_gate_tu32j_1_2 >"${run_dir}/logs/targeted_tests.log" 2>&1
  else
    printf 'CARGO_TARGET_DIR=%q cargo test --locked --manifest-path %q --test executable_output_truth_gate_tu32j_1_2\n' \
      "$target_dir" "$tool_manifest" >>"$commands_path"
    CARGO_TARGET_DIR="$target_dir" cargo test --locked --manifest-path "$tool_manifest" \
      --test executable_output_truth_gate_tu32j_1_2 >"${run_dir}/logs/targeted_tests.log" 2>&1
  fi
  append_event "gate.targeted_tests" "pass" "executable_output_truth_gate_tu32j_1_2 passed"
fi

printf '%q audit-output-claims --repo-root %q --events %q --run-id %q --trace-id %q\n' \
  "$validator_bin" "$root_dir" "$audit_events_path" "$run_id" "$trace_id" >>"$commands_path"
"$validator_bin" audit-output-claims \
  --repo-root "$root_dir" \
  --events "$audit_events_path" \
  --run-id "$run_id" \
  --trace-id "$trace_id" >"$audit_report_path" 2>"${run_dir}/logs/audit.stderr.log"
append_event "gate.live_audit" "pass" "live repository claim-language audit passed"

printf 'python3 scripts/challenge_executable_output_truth_gate.py --repo-root %q --validator-bin %q --work-dir %q --out %q\n' \
  "$root_dir" "$validator_bin" "$run_dir" "$challenge_handoff_path" >>"$commands_path"
python3 scripts/challenge_executable_output_truth_gate.py \
  --repo-root "$root_dir" \
  --validator-bin "$validator_bin" \
  --work-dir "$run_dir" \
  --out "$challenge_handoff_path" >"${run_dir}/logs/challenge.stdout.json"
append_event "gate.neutral_challenge" "pass" "10/10 positive and seeded negative challenges passed"

git_rev="$(git rev-parse HEAD 2>/dev/null || echo unknown)"
jq -n \
  --arg schema_version "franken-engine.executable-output-truth-gate.env.v1" \
  --arg git_rev "$git_rev" \
  --arg platform "$(uname -srm 2>/dev/null || echo unknown)" \
  --arg toolchain "$toolchain" \
  '{schema_version: $schema_version, git_rev: $git_rev, platform: $platform, toolchain: $toolchain}' >"$env_path"

cat >"$legal_path" <<'EOF'
# Legal & Corpus Provenance (BRIDGE-00.2)

- Repository license: MIT (`LICENSE`).
- Governed Test262 reference metadata (`docs/test262_real_corpus_pass_rate_v1.json`): BSD-3-Clause TC39 Test262 metadata only; no third-party proprietary corpus files are redistributed in this bundle.
EOF

cat >"$rollback_path" <<'EOF'
# Rollback & Safe Fallback (BRIDGE-00.2)

- Every gate execution writes exclusively to a fresh timestamped `artifacts/executable_output_truth_gate/<run_id>/` prefix and never mutates tracked files in place.
- If a claim-language or bundle promotion fails closed (`exit 1`), retain conservative claim states (`target` / `hypothesis`), preserve the failing run bundle for triage, and revert the offending wording or unverified bundle before merge.
EOF

jq -n \
  --arg schema_version "franken-engine.executable-output-truth-gate.provenance.v1" \
  --arg owning_bead "bd-performance-conformance-bridge-tu32j.1.2" \
  --arg upstream_bead "bd-performance-conformance-bridge-tu32j.1.1" \
  --arg downstream_capstone "bd-performance-conformance-bridge-tu32j.1.4" \
  '{
    schema_version: $schema_version,
    owning_bead: $owning_bead,
    edges: [
      {from: $upstream_bead, relation: "supplies_truth_ledger_to", to: $owning_bead},
      {from: $owning_bead, relation: "publishes_challenge_handoff_to", to: $downstream_capstone}
    ]
  }' >"$provenance_path"

audit_sha="$(proof_contract_sha256_file "$audit_report_path")"
handoff_sha="$(proof_contract_sha256_file "$challenge_handoff_path")"
commands_sha="$(proof_contract_sha256_file "$commands_path")"
events_sha="$(proof_contract_sha256_file "$events_path")"

jq -n \
  --arg schema_version "franken-engine.executable-output-truth-gate.repro-lock.v1" \
  --arg git_rev "$git_rev" \
  --arg command "./scripts/run_executable_output_truth_gate.sh ${mode}" \
  --arg audit_report_sha256 "$audit_sha" \
  --arg challenge_handoff_sha256 "$handoff_sha" \
  '{
    schema_version: $schema_version,
    source_commit: $git_rev,
    reproduce_command: $command,
    cleanup_command: "none (preserve RCH target dir and immutable run prefix)",
    expected_outputs: {
      verdict: "pass",
      audit_report_sha256: $audit_report_sha256,
      challenge_handoff_sha256: $challenge_handoff_sha256
    }
  }' >"$repro_lock_path"

jq -n \
  --arg schema_version "franken-engine.executable-output-truth-gate.run-manifest.v1" \
  --arg owning_bead "bd-performance-conformance-bridge-tu32j.1.2" \
  --arg mode "$mode" \
  --arg verdict "pass" \
  --arg run_id "$run_id" \
  --arg trace_id "$trace_id" \
  --arg git_rev "$git_rev" \
  --arg audit_sha "$audit_sha" \
  --arg handoff_sha "$handoff_sha" \
  --arg commands_sha "$commands_sha" \
  --arg events_sha "$events_sha" \
  '{
    schema_version: $schema_version,
    owning_bead: $owning_bead,
    mode: $mode,
    verdict: $verdict,
    run_id: $run_id,
    trace_id: $trace_id,
    git_rev: $git_rev,
    artifact_hashes: {
      "audit_report.json": $audit_sha,
      "challenge_handoff.json": $handoff_sha,
      "commands.txt": $commands_sha,
      "events.jsonl": $events_sha
    }
  }' >"$manifest_path"

append_event "gate.end" "pass" "manifest=${manifest_path}"
echo "executable_output_truth_gate: PASS (${manifest_path})"
