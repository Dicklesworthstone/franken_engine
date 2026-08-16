#!/usr/bin/env bash
# Executable verification-coverage contract gate.
#
# The certifying path is deliberately one-way:
#   source identity -> RCH-admitted coordinator-observed tools/tests
#   -> live generate/render/validate
#   -> deterministic replay -> real provisional franken-core probe -> frozen
#   evidence -> provenance -> no-replace artifact manifest -> bundle validation.
#
# A failed or interrupted run is retained at its unique artifact prefix.  This
# script never edits the committed contract or generated Markdown.
set -Eeuo pipefail
set -o noclobber

root_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$root_dir"

source_identity() {
  python3 - "$root_dir" <<'PY'
import hashlib
import os
import stat
import struct
import subprocess
import sys

root = os.fsencode(os.path.realpath(sys.argv[1]))
listed = subprocess.run(
    ["git", "-C", os.fsdecode(root), "ls-files", "-co", "--exclude-standard", "-z"],
    check=True,
    stdout=subprocess.PIPE,
).stdout
paths = sorted(path for path in listed.split(b"\0") if path)
if len(paths) != len(set(paths)):
    raise SystemExit("source identity refused duplicate Git source paths")

digest = hashlib.sha256()
for relative in paths:
    if relative.startswith(b"/") or b"\0" in relative:
        raise SystemExit("source identity refused an unsafe source path")
    components = relative.split(b"/")
    if not components or any(component in (b"", b".", b"..") for component in components):
        raise SystemExit("source identity refused a non-normal source path")
    absolute = root + b"/" + relative
    if not hasattr(os, "O_NOFOLLOW"):
        raise SystemExit("source identity requires O_NOFOLLOW support")
    try:
        descriptor = os.open(
            absolute,
            os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW,
        )
    except OSError as error:
        raise SystemExit(
            "source identity refused an unreadable or symlink source: "
            + os.fsdecode(relative)
            + f": {error}"
        ) from error
    try:
        before = os.fstat(descriptor)
        if not stat.S_ISREG(before.st_mode):
            raise SystemExit(
                "source identity requires regular non-symlink files: "
                + os.fsdecode(relative)
            )
        mode = b"100755" if before.st_mode & 0o111 else b"100644"
        digest.update(struct.pack("<Q", len(relative)))
        digest.update(relative)
        digest.update(struct.pack("<Q", len(mode)))
        digest.update(mode)
        digest.update(struct.pack("<Q", before.st_size))
        bytes_read = 0
        while True:
            content = os.read(descriptor, 1024 * 1024)
            if not content:
                break
            bytes_read += len(content)
            digest.update(content)
        after = os.fstat(descriptor)
        stable_fields = (
            "st_dev",
            "st_ino",
            "st_mode",
            "st_size",
            "st_mtime_ns",
        )
        if bytes_read != before.st_size or any(
            getattr(before, field) != getattr(after, field)
            for field in stable_fields
        ):
            raise SystemExit(
                "source identity refused a file that changed during hashing: "
                + os.fsdecode(relative)
            )
    finally:
        os.close(descriptor)
print(digest.hexdigest())
PY
}

reject_rch_fallback_log() {
  local log_path="$1"
  if grep -Eiq \
    'falling back to local|fallback to local|local fallback|\[RCH\][[:space:]]+local[[:space:]]*\(|remote execution failed.*running locally|dependency preflight blocked remote execution|exec called with non-compilation command|RCH-E326' \
    "$log_path"; then
    echo "refusing RCH output that reports local fallback: ${log_path}" >&2
    return 1
  fi
}

if [[ "${1:-}" == "source-identity" ]]; then
  if [[ "$#" -ne 1 ]]; then
    echo "usage: $0 source-identity" >&2
    exit 2
  fi
  source_identity
  exit 0
fi

if [[ "${1:-}" == "audit-rch-log" ]]; then
  if [[ "$#" -ne 2 || ! -f "$2" ]]; then
    echo "usage: $0 audit-rch-log <regular-log-file>" >&2
    exit 2
  fi
  reject_rch_fallback_log "$2"
  exit 0
fi

mode="${1:-ci}"
case "$mode" in
  check | ci) ;;
  *)
    echo "usage: $0 [check|ci] [unique-run-directory]" >&2
    exit 2
    ;;
esac

timestamp="$(date -u +%Y%m%dT%H%M%SZ)"
artifact_root="${VERIFICATION_COVERAGE_CONTRACT_ARTIFACT_ROOT:-artifacts/verification_coverage_contract}"
run_dir="${2:-${artifact_root}/${timestamp}-$$}"
case "$run_dir" in
  /*) ;;
  *) run_dir="${root_dir}/${run_dir}" ;;
esac
run_dir="${run_dir%/}"

tool_manifest="tools/execution-truth-ledger/Cargo.toml"
tool_lock_source="tools/execution-truth-ledger/Cargo.lock"
contract_source="docs/verification_coverage_contract_v1.json"
markdown_source="docs/VERIFICATION_COVERAGE_CONTRACT_V1.md"
root_lock_source="Cargo.lock"
toolchain="${RUSTUP_TOOLCHAIN:-nightly}"
rch_bin="${VERIFICATION_COVERAGE_CONTRACT_RCH_BIN:-rch}"
rch_timeout_seconds="${RCH_EXEC_TIMEOUT_SECONDS:-1800}"
runtime_timeout_seconds="${VCC_RUNTIME_TIMEOUT_SECONDS:-300}"
target_base="${VERIFICATION_COVERAGE_CONTRACT_CARGO_TARGET_BASE:-/tmp/rch_target_franken_engine_vcc}"
case "$target_base" in
  /*) ;;
  *) target_base="${root_dir}/${target_base}" ;;
esac
build_target_dir="${target_base}_build_${timestamp}_$$"
test_target_dir="${target_base}_test_${timestamp}_$$"
run_id="run-verification-coverage-contract-${timestamp}-$$"
trace_id="trace-verification-coverage-contract-${timestamp}-$$"
test_id="verification-coverage-contract-gate"
scenario_id="canonical-${mode}"
seed="${VERIFICATION_COVERAGE_CONTRACT_SEED:-424242}"
attempt=1
platform="$(uname -s 2>/dev/null || printf unknown)-$(uname -m 2>/dev/null || printf unknown)"
tier="verification-control-plane"
security_profile="evidence-on"
source_identity_command="./scripts/run_verification_coverage_contract_gate.sh source-identity"
source_tree_basis="sorted-relative-path-mode-length-and-bytes-sha256-v1"
source_diff_basis="git-binary-patch-including-untracked-v1"

phase_events_path="${run_dir}/phase_events.jsonl"
manifest_published=false
phase_sequence=0
first_failure_phase=""
first_failure_code=""
declare -a recorded_commands=()
admitted_worker=""

sha256_file() {
  sha256sum "$1" | awk '{print $1}'
}

shell_join() {
  local rendered=""
  local argument
  for argument in "$@"; do
    printf -v rendered '%s%q ' "$rendered" "$argument"
  done
  printf '%s' "${rendered% }"
}

record_command() {
  recorded_commands+=("$1")
}

redact_text() {
  sed -E \
    's/(authorization:|bearer[[:space:]]+|api_key=|apikey=|password=|secret=|token=|private_key=|--token[[:space:]]+|--password[[:space:]]+|--secret[[:space:]]+|--api-key[[:space:]]+)[^[:space:],;]+/\1<redacted>/Ig'
}

append_phase() {
  local phase="$1"
  local decision="$2"
  local exit_code="$3"
  local duration_ms="$4"
  local reason="$5"
  local stdout_path="${6:-}"
  local stderr_path="${7:-}"
  local stdout_sha=""
  local stderr_sha=""
  local redacted_reason
  phase_sequence=$((phase_sequence + 1))
  redacted_reason="$(printf '%s' "$reason" | redact_text)"
  if [[ -n "$stdout_path" && -f "${run_dir}/${stdout_path}" ]]; then
    stdout_sha="$(sha256_file "${run_dir}/${stdout_path}")"
  fi
  if [[ -n "$stderr_path" && -f "${run_dir}/${stderr_path}" ]]; then
    stderr_sha="$(sha256_file "${run_dir}/${stderr_path}")"
  fi
  jq -nc \
    --arg schema_version "franken-engine.verification-coverage-contract.gate-phase.v1" \
    --arg run_id "$run_id" \
    --arg trace_id "$trace_id" \
    --arg test_id "$test_id" \
    --arg scenario_id "$scenario_id" \
    --argjson seed "$seed" \
    --argjson attempt "$attempt" \
    --arg phase "$phase" \
    --argjson sequence "$phase_sequence" \
    --arg decision "$decision" \
    --argjson exit_code "$exit_code" \
    --argjson duration_ms "$duration_ms" \
    --arg reason "${redacted_reason:0:768}" \
    --arg stdout_path "$stdout_path" \
    --arg stderr_path "$stderr_path" \
    --arg stdout_sha "$stdout_sha" \
    --arg stderr_sha "$stderr_sha" \
    --arg at_utc "$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
    '{
      schema_version:$schema_version,
      run_id:$run_id,
      trace_id:$trace_id,
      test_id:$test_id,
      scenario_id:$scenario_id,
      seed:$seed,
      attempt:$attempt,
      phase:$phase,
      sequence:$sequence,
      decision:$decision,
      exit_code:$exit_code,
      duration_ms:$duration_ms,
      reason:$reason,
      observed_at_utc:$at_utc,
      stdout:(if $stdout_path == "" then null else {
        path:$stdout_path,
        sha256:(if $stdout_sha == "" then null else $stdout_sha end)
      } end),
      stderr:(if $stderr_path == "" then null else {
        path:$stderr_path,
        sha256:(if $stderr_sha == "" then null else $stderr_sha end)
      } end)
    }' >>"$phase_events_path"
}

fail_gate() {
  local phase="$1"
  local exit_code="$2"
  local reason="$3"
  local stdout_path="${4:-}"
  local stderr_path="${5:-}"
  if [[ -z "$first_failure_phase" ]]; then
    first_failure_phase="$phase"
    first_failure_code="$exit_code"
  fi
  if [[ -d "$run_dir" && "$manifest_published" == false ]]; then
    append_phase "$phase" "fail" "$exit_code" 0 "$reason" "$stdout_path" "$stderr_path"
  fi
  echo "verification coverage gate failed at ${phase}: ${reason}" >&2
  echo "first_failure_phase=${first_failure_phase}" >&2
  echo "first_failure_exit=${first_failure_code}" >&2
  echo "recoverable_run_dir=${run_dir}" >&2
  exit "$exit_code"
}

on_exit() {
  local status="$?"
  if [[ "$status" -ne 0 ]]; then
    if [[ -d "$run_dir" ]]; then
      echo "verification coverage gate retained its no-overwrite evidence prefix: ${run_dir}" >&2
    else
      echo "verification coverage gate failed before creating its evidence prefix: ${run_dir}" >&2
    fi
  fi
}
trap on_exit EXIT

preflight_tools=(
  awk cargo cmp cp date diff find git grep jq mkdir python3 rustc sed sha256sum
  sort stat timeout uname
)
for required_tool in "${preflight_tools[@]}"; do
  command -v "$required_tool" >/dev/null 2>&1 || {
    echo "missing required tool: ${required_tool}" >&2
    exit 2
  }
done
command -v "$rch_bin" >/dev/null 2>&1 || {
  echo "missing required RCH executable: ${rch_bin}" >&2
  exit 2
}
for required_file in \
  "$tool_manifest" \
  "$tool_lock_source" \
  "$contract_source" \
  "$markdown_source" \
  "$root_lock_source"; do
  [[ -f "$required_file" && ! -L "$required_file" ]] || {
    echo "missing required regular input: ${required_file}" >&2
    exit 2
  }
done
[[ "$seed" =~ ^[0-9]+$ ]] || {
  echo "VERIFICATION_COVERAGE_CONTRACT_SEED must be an unsigned integer" >&2
  exit 2
}
[[ "$rch_timeout_seconds" =~ ^[1-9][0-9]*$ ]] || {
  echo "RCH_EXEC_TIMEOUT_SECONDS must be a positive integer" >&2
  exit 2
}
[[ "$runtime_timeout_seconds" =~ ^[1-9][0-9]*$ ]] || {
  echo "VCC_RUNTIME_TIMEOUT_SECONDS must be a positive integer" >&2
  exit 2
}
if [[ -e "$run_dir" ]]; then
  echo "refusing to overwrite existing verification bundle prefix: ${run_dir}" >&2
  exit 2
fi
for cargo_target_dir in "$build_target_dir" "$test_target_dir"; do
  if [[ -e "$cargo_target_dir" ]]; then
    echo "refusing to reuse existing verification Cargo target: ${cargo_target_dir}" >&2
    exit 2
  fi
done

# Snapshot the certifying source closure before the run directory exists.
initial_source_tree_sha="$(./scripts/run_verification_coverage_contract_gate.sh source-identity)"
[[ "$initial_source_tree_sha" =~ ^[0-9a-f]{64}$ ]] || {
  echo "source identity did not produce a lowercase SHA-256 digest" >&2
  exit 2
}
repository_revision="$(git rev-parse HEAD)"
[[ "$repository_revision" =~ ^[0-9a-f]{40}$|^[0-9a-f]{64}$ ]] || {
  echo "repository revision is not a supported Git object ID" >&2
  exit 2
}
source_status="$(git status --porcelain=v1 --untracked-files=all)"
source_state="clean"
if [[ -n "$source_status" ]]; then
  source_state="dirty"
fi
declare -a initial_untracked_files=()
while IFS= read -r -d '' untracked_path; do
  initial_untracked_files+=("$untracked_path")
done < <(git ls-files --others --exclude-standard -z)

mkdir -p "$(dirname "$run_dir")"
mkdir "$run_dir"
append_phase "gate.preflight" "pass" 0 0 \
  "required tools, locked manifests, canonical inputs, and unique output prefix are present"
append_phase "source.identity.initial" "pass" 0 0 \
  "source identity ${initial_source_tree_sha}; state ${source_state}"
record_command "$source_identity_command"

run_rch() {
  local cargo_target_dir="$1"
  shift
  [[ -n "$admitted_worker" ]] || return 84
  env -u CARGO_ENCODED_RUSTFLAGS -u RCH_MOCK_SSH -u RCH_TEST_MODE \
    RCH_REQUIRE_REMOTE=1 \
    RCH_NO_SELF_HEALING=1 \
    RCH_WORKER="$admitted_worker" \
    RCH_BUILD_TIMEOUT_SEC="$rch_timeout_seconds" \
    RCH_TEST_TIMEOUT_SEC="$rch_timeout_seconds" \
    RUSTUP_TOOLCHAIN="$toolchain" \
    CARGO_TARGET_DIR="$cargo_target_dir" \
    CARGO_INCREMENTAL=0 \
    RUSTFLAGS="-C linker=cc -Clinker-features=-lld" \
    timeout "$rch_timeout_seconds" \
    "$rch_bin" --no-self-healing exec -- \
    env RUSTUP_TOOLCHAIN="$toolchain" RCH_WORKER_ID="$admitted_worker" "$@"
}

rch_command_text() {
  local cargo_target_dir="$1"
  shift
  shell_join \
    env -u CARGO_ENCODED_RUSTFLAGS -u RCH_MOCK_SSH -u RCH_TEST_MODE \
    RCH_REQUIRE_REMOTE=1 \
    RCH_NO_SELF_HEALING=1 \
    "RCH_WORKER=${admitted_worker}" \
    "RCH_BUILD_TIMEOUT_SEC=${rch_timeout_seconds}" \
    "RCH_TEST_TIMEOUT_SEC=${rch_timeout_seconds}" \
    "RUSTUP_TOOLCHAIN=${toolchain}" \
    "CARGO_TARGET_DIR=${cargo_target_dir}" \
    CARGO_INCREMENTAL=0 \
    "RUSTFLAGS=-C linker=cc -Clinker-features=-lld" \
    timeout "$rch_timeout_seconds" \
    "$rch_bin" --no-self-healing exec -- \
    env "RUSTUP_TOOLCHAIN=${toolchain}" "RCH_WORKER_ID=${admitted_worker}" "$@"
}

rch_diagnose_command_text() {
  local cargo_target_dir="$1"
  shift
  shell_join \
    env -u CARGO_ENCODED_RUSTFLAGS -u RCH_MOCK_SSH -u RCH_TEST_MODE \
    RCH_REQUIRE_REMOTE=1 \
    RCH_NO_SELF_HEALING=1 \
    "RUSTUP_TOOLCHAIN=${toolchain}" \
    "CARGO_TARGET_DIR=${cargo_target_dir}" \
    CARGO_INCREMENTAL=0 \
    "RUSTFLAGS=-C linker=cc -Clinker-features=-lld" \
    timeout "$runtime_timeout_seconds" \
    "$rch_bin" diagnose --json -- "$@"
}

run_rch_admission_phase() {
  local phase="$1"
  local report_name="$2"
  local stderr_name="$3"
  local cargo_target_dir="$4"
  shift 4
  local command_text
  local started_ns
  local ended_ns
  local duration_ms
  local status=0
  local selected_worker
  local selection_reason
  command_text="$(rch_diagnose_command_text "$cargo_target_dir" "$@")"
  record_command "$command_text"
  started_ns="$(date +%s%N)"
  set +e
  env -u CARGO_ENCODED_RUSTFLAGS -u RCH_MOCK_SSH -u RCH_TEST_MODE \
    RCH_REQUIRE_REMOTE=1 \
    RCH_NO_SELF_HEALING=1 \
    RUSTUP_TOOLCHAIN="$toolchain" \
    CARGO_TARGET_DIR="$cargo_target_dir" \
    CARGO_INCREMENTAL=0 \
    RUSTFLAGS="-C linker=cc -Clinker-features=-lld" \
    timeout "$runtime_timeout_seconds" \
    "$rch_bin" diagnose --json -- "$@" \
    >"${run_dir}/${report_name}" 2>"${run_dir}/${stderr_name}"
  status="$?"
  set -e
  ended_ns="$(date +%s%N)"
  duration_ms=$(((ended_ns - started_ns) / 1000000))
  if [[ "$status" -ne 0 ]]; then
    append_phase "$phase" "fail" "$status" "$duration_ms" \
      "RCH admission diagnostic exited ${status}" "$report_name" "$stderr_name"
    return "$status"
  fi
  if ! jq -e '
    .api_version == "1.0"
    and .command == "diagnose"
    and .success == true
    and .data.classification.is_compilation == true
    and .data.decision.would_intercept == true
    and (.data.worker_selection.worker.id | type == "string" and length > 0)
  ' "${run_dir}/${report_name}" >/dev/null; then
    selection_reason="$(jq -r \
      '.data.worker_selection.reason // .data.decision.reason // "malformed_diagnostic"' \
      "${run_dir}/${report_name}" 2>/dev/null || printf malformed_diagnostic)"
    append_phase "$phase" "fail" 85 "$duration_ms" \
      "RCH admission found no eligible worker (${selection_reason}); this diagnostic is admission evidence, not an execution-completion receipt" \
      "$report_name" "$stderr_name"
    return 85
  fi
  selected_worker="$(jq -r '.data.worker_selection.worker.id' \
    "${run_dir}/${report_name}")"
  admitted_worker="$selected_worker"
  append_phase "$phase" "pass" 0 "$duration_ms" \
    "RCH admission selected eligible worker ${selected_worker}; this is advisory admission evidence, not an execution-completion receipt" \
    "$report_name" "$stderr_name"
}

run_rch_phase() {
  local phase="$1"
  local stdout_name="$2"
  local stderr_name="$3"
  local cargo_target_dir="$4"
  shift 4
  local command_text
  local started_ns
  local ended_ns
  local duration_ms
  local status=0
  command_text="$(rch_command_text "$cargo_target_dir" "$@")"
  record_command "$command_text"
  started_ns="$(date +%s%N)"
  set +e
  run_rch "$cargo_target_dir" "$@" \
    >"${run_dir}/${stdout_name}" 2>"${run_dir}/${stderr_name}"
  status="$?"
  set -e
  ended_ns="$(date +%s%N)"
  duration_ms=$(((ended_ns - started_ns) / 1000000))
  if ! reject_rch_fallback_log "${run_dir}/${stdout_name}" \
    || ! reject_rch_fallback_log "${run_dir}/${stderr_name}"; then
    status=86
  fi
  if grep -Eiq \
    'artifact retrieval failed|failed to retrieve artifacts|rsync artifact retrieval failed|rsync error:.*code 23' \
    "${run_dir}/${stdout_name}" "${run_dir}/${stderr_name}"; then
    status=87
  fi
  if ! grep -Fq "Selected worker: ${admitted_worker} at " \
    "${run_dir}/${stdout_name}" "${run_dir}/${stderr_name}"; then
    status=88
  fi
  if [[ "$status" -ne 0 ]]; then
    append_phase "$phase" "fail" "$status" "$duration_ms" \
      "RCH coordinator command exited ${status}; local fallback is forbidden" \
      "$stdout_name" "$stderr_name"
    return "$status"
  fi
  append_phase "$phase" "pass" 0 "$duration_ms" \
    "RCH coordinator reported success and no recognized fallback marker; completion is coordinator-observed and unattested, not a cryptographic worker receipt" \
    "$stdout_name" "$stderr_name"
}

build_stdout="build.stdout.log"
build_stderr="build.stderr.log"
build_diagnose="build.rch_diagnose.json"
build_diagnose_stderr="build.rch_diagnose.stderr.log"
build_argv=(
  cargo build --locked --release --manifest-path "$tool_manifest"
  --features tier-r-probe
  --bin franken_verification_coverage_contract
  --bin franken_provisional_tier_r_probe
)
if run_rch_admission_phase "tool.build.admission" \
  "$build_diagnose" "$build_diagnose_stderr" "$build_target_dir" \
  "${build_argv[@]}"; then
  :
else
  status="$?"
  fail_gate "tool.build.admission" "$status" \
    "RCH did not admit the locked build to an eligible worker; inspect the retained typed diagnostic" \
    "$build_diagnose" "$build_diagnose_stderr"
fi
build_worker="$admitted_worker"
build_worker_sha="$(printf '%s' "$build_worker" | sha256sum | awk '{print $1}')"
if run_rch_phase "tool.build" "$build_stdout" "$build_stderr" \
  "$build_target_dir" "${build_argv[@]}"; then
  :
else
  status="$?"
  fail_gate "tool.build" "$status" "locked RCH build failed" "$build_stdout" "$build_stderr"
fi

built_validator_bin="${build_target_dir}/release/franken_verification_coverage_contract"
built_probe_bin="${build_target_dir}/release/franken_provisional_tier_r_probe"
for built_binary in "$built_validator_bin" "$built_probe_bin"; do
  [[ -f "$built_binary" && -x "$built_binary" && ! -L "$built_binary" ]] || \
    fail_gate "tool.artifact_retrieval" 88 \
      "RCH reported success but did not retrieve executable ${built_binary}" \
      "$build_stdout" "$build_stderr"
done
built_validator_sha="$(sha256_file "$built_validator_bin")"
built_probe_sha="$(sha256_file "$built_probe_bin")"
validator_bin="${run_dir}/verification_coverage_contract_validator"
probe_bin="${run_dir}/tier_r_probe_executable"
cp --no-clobber "$built_validator_bin" "$validator_bin"
cp --no-clobber "$built_probe_bin" "$probe_bin"
[[ -f "$validator_bin" && -x "$validator_bin" && ! -L "$validator_bin" \
  && "$(sha256_file "$validator_bin")" == "$built_validator_sha" ]] \
  || fail_gate "tool.artifact_retrieval" 88 \
    "retained validator executable differs from the coordinator-retrieved build output" \
    "$build_stdout" "$build_stderr"
[[ -f "$probe_bin" && -x "$probe_bin" && ! -L "$probe_bin" \
  && "$(sha256_file "$probe_bin")" == "$built_probe_sha" ]] \
  || fail_gate "tool.artifact_retrieval" 88 \
    "retained Tier-R executable differs from the coordinator-retrieved build output" \
    "$build_stdout" "$build_stderr"
append_phase "tool.artifact_retrieval" "pass" 0 0 \
  "both coordinator-reported build outputs were immediately retained and SHA-256 bound (validator ${built_validator_sha}; Tier-R ${built_probe_sha})"

tests_stdout="tests.stdout.log"
tests_stderr="tests.stderr.log"
tests_diagnose="tests.rch_diagnose.json"
tests_diagnose_stderr="tests.rch_diagnose.stderr.log"
tests_argv=(
  cargo test --locked --manifest-path "$tool_manifest"
  --features tier-r-probe
  --test verification_coverage_contract_integration
  --
  --nocapture
)
if run_rch_admission_phase "tool.tests.admission" \
  "$tests_diagnose" "$tests_diagnose_stderr" "$test_target_dir" \
  "${tests_argv[@]}"; then
  :
else
  status="$?"
  fail_gate "tool.tests.admission" "$status" \
    "RCH did not admit the focused integration suite to an eligible worker; inspect the retained typed diagnostic" \
    "$tests_diagnose" "$tests_diagnose_stderr"
fi
if run_rch_phase "tool.tests" "$tests_stdout" "$tests_stderr" \
  "$test_target_dir" "${tests_argv[@]}"; then
  :
else
  status="$?"
  fail_gate "tool.tests" "$status" "locked focused integration suite failed" \
    "$tests_stdout" "$tests_stderr"
fi
if ! grep -Eq \
  'test result: ok\.[[:space:]]+[1-9][0-9]* passed;[[:space:]]+0 failed' \
  "${run_dir}/${tests_stdout}" "${run_dir}/${tests_stderr}"; then
  fail_gate "tool.tests.nonzero" 89 \
    "focused test command did not prove that at least one test ran and passed" \
    "$tests_stdout" "$tests_stderr"
fi
append_phase "tool.tests.nonzero" "pass" 0 0 \
  "focused integration suite executed a nonzero number of tests"
if [[ "$(sha256_file "$built_validator_bin")" != "$built_validator_sha" \
  || "$(sha256_file "$built_probe_bin")" != "$built_probe_sha" \
  || "$(sha256_file "$validator_bin")" != "$built_validator_sha" \
  || "$(sha256_file "$probe_bin")" != "$built_probe_sha" ]]; then
  fail_gate "tool.artifact_rehash" 88 \
    "a retained or coordinator-retrieved executable changed after the isolated test build"
fi
append_phase "tool.artifact_rehash" "pass" 0 0 \
  "separate test-target execution left both retained and coordinator-retrieved build executables byte-identical"

created_at_utc="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
canonical_contract_before="$(sha256_file "$contract_source")"
canonical_markdown_before="$(sha256_file "$markdown_source")"

cp --no-clobber "$contract_source" "${run_dir}/contract.json"
cp --no-clobber "$root_lock_source" "${run_dir}/root.Cargo.lock"
cp --no-clobber "$tool_lock_source" "${run_dir}/tool.Cargo.lock"
: >"${run_dir}/guest.stdout.log"
: >"${run_dir}/guest.stderr.log"

run_local_capture() {
  local phase="$1"
  local stdout_name="$2"
  local stderr_name="$3"
  shift 3
  local command_text
  local started_ns
  local ended_ns
  local duration_ms
  local status=0
  command_text="$(shell_join timeout "$runtime_timeout_seconds" "$@")"
  record_command "$command_text"
  started_ns="$(date +%s%N)"
  set +e
  timeout "$runtime_timeout_seconds" "$@" \
    >"${run_dir}/${stdout_name}" 2>"${run_dir}/${stderr_name}"
  status="$?"
  set -e
  ended_ns="$(date +%s%N)"
  duration_ms=$(((ended_ns - started_ns) / 1000000))
  if [[ "$status" -ne 0 ]]; then
    append_phase "$phase" "fail" "$status" "$duration_ms" \
      "runtime command exited ${status}" "$stdout_name" "$stderr_name"
    return "$status"
  fi
  append_phase "$phase" "pass" 0 "$duration_ms" \
    "runtime command completed" "$stdout_name" "$stderr_name"
}

if run_local_capture "contract.generate" "generated_contract.json" "generate.stderr.log" \
  "$validator_bin" generate --repo-root "$root_dir"; then
  :
else
  status="$?"
  fail_gate "contract.generate" "$status" "live contract generation failed" \
    "generated_contract.json" "generate.stderr.log"
fi
if ! cmp -s "${run_dir}/contract.json" "${run_dir}/generated_contract.json"; then
  fail_gate "contract.generation_drift" 90 \
    "committed and live-generated contracts are not byte-identical"
fi
append_phase "contract.generation_drift" "pass" 0 0 \
  "committed and live-generated contracts are byte-identical"

if run_local_capture "contract.render" "rendered_contract.md" "render.stderr.log" \
  "$validator_bin" render --repo-root "$root_dir" \
    --contract "${run_dir}/contract.json"; then
  :
else
  status="$?"
  fail_gate "contract.render" "$status" "deterministic renderer failed" \
    "rendered_contract.md" "render.stderr.log"
fi
if ! cmp -s "$markdown_source" "${run_dir}/rendered_contract.md"; then
  fail_gate "contract.markdown_drift" 91 \
    "committed Markdown differs from the deterministic renderer"
fi
append_phase "contract.markdown_drift" "pass" 0 0 \
  "committed Markdown matches the deterministic renderer"

reproduction_started_at="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
target="$(RUSTUP_TOOLCHAIN="$toolchain" rustc -vV | sed -n 's/^host: //p')"
if [[ -z "$target" ]]; then
  fail_gate "environment.target" 92 "rustc did not report a host target"
fi
validate_argv=(
  "$validator_bin" validate
  --repo-root "$root_dir"
  --contract "$contract_source"
  --run-id "$run_id"
  --trace-id "$trace_id"
  --test-id "$test_id"
  --scenario-id "$scenario_id"
  --seed "$seed"
  --attempt "$attempt"
  --platform "$platform"
  --target "$target"
  --tier "$tier"
  --profile "$security_profile"
)
if run_local_capture "contract.validate" \
  "reproduction.stdout.log" "reproduction.stderr.log" "${validate_argv[@]}"; then
  :
else
  status="$?"
  fail_gate "contract.validate" "$status" \
    "live validation did not produce a passing envelope" \
    "reproduction.stdout.log" "reproduction.stderr.log"
fi
reproduction_command="$(shell_join timeout "$runtime_timeout_seconds" "${validate_argv[@]}")"
if ! jq -se '
  length == 1
  and (.[0] |
    (keys | sort) == ["events","report"]
    and (.report | type == "object")
    and (.report.status == "pass")
    and (.report.error_count == 0)
    and (.events | type == "array" and length > 1)
  )
' "${run_dir}/reproduction.stdout.log" >/dev/null; then
  fail_gate "contract.envelope" 93 \
    "validator stdout is not one passing {report,events} JSON envelope" \
    "reproduction.stdout.log" "reproduction.stderr.log"
fi
jq -S '.report' "${run_dir}/reproduction.stdout.log" \
  >"${run_dir}/validation_report.json"
jq -c '.events[]' "${run_dir}/reproduction.stdout.log" \
  >"${run_dir}/events.jsonl"
append_phase "contract.envelope" "pass" 0 0 \
  "validator emitted exactly one report/events envelope; retained streams were split without changing the envelope"

if run_local_capture "events.validate" \
  "event_validation_report.json" "event_validation.stderr.log" \
  "$validator_bin" validate-events --events "${run_dir}/events.jsonl"; then
  :
else
  status="$?"
  fail_gate "events.validate" "$status" "retained event stream failed strict validation" \
    "event_validation_report.json" "event_validation.stderr.log"
fi
jq -se '
  length == 1
  and (.[0] | .status == "pass" and .error_count == 0 and .event_count > 1)
' \
  "${run_dir}/event_validation_report.json" >/dev/null \
  || fail_gate "events.validate.report" 94 \
    "event validator report did not prove a nonempty passing stream" \
    "event_validation_report.json" "event_validation.stderr.log"

if run_local_capture "contract.replay" \
  "replay.stdout.log" "replay.stderr.log" "${validate_argv[@]}"; then
  :
else
  status="$?"
  fail_gate "contract.replay" "$status" "second live validation failed" \
    "replay.stdout.log" "replay.stderr.log"
fi
if ! cmp -s \
  <(jq -S '
    .report.as_of_utc = "<normalized>"
    | .events |= map(
        .duration_ns = 0
        | .resource_delta.wall_time_ns = 0
        | if .phase == "contract.freshness"
            and .reason_code == "FE-VCC-0000"
          then .reason |= sub(
            "^source cutoff is [0-9]+ seconds";
            "source cutoff is <normalized> seconds"
          )
          else .
          end
      )
  ' "${run_dir}/reproduction.stdout.log") \
  <(jq -S '
    .report.as_of_utc = "<normalized>"
    | .events |= map(
        .duration_ns = 0
        | .resource_delta.wall_time_ns = 0
        | if .phase == "contract.freshness"
            and .reason_code == "FE-VCC-0000"
          then .reason |= sub(
            "^source cutoff is [0-9]+ seconds";
            "source cutoff is <normalized> seconds"
          )
          else .
          end
      )
  ' "${run_dir}/replay.stdout.log"); then
  fail_gate "contract.replay.drift" 95 \
    "replay differed after normalizing only witnessed clock and measured duration fields" \
    "replay.stdout.log" "replay.stderr.log"
fi
append_phase "contract.replay.drift" "pass" 0 0 \
  "independent replay matched after normalizing witnessed clock-derived age and measured duration fields"

tier_started_at="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
tier_argv=(
  env
  "VCC_RUN_ID=${run_id}"
  "VCC_TRACE_ID=${trace_id}"
  "VCC_TIER_R_SOURCE_MANIFEST_OUTPUT=${run_dir}/tier_r_source_manifest.json"
  "VCC_TIER_R_BUILD_ENVIRONMENT_OUTPUT=${run_dir}/tier_r_build_environment.json"
  "${run_dir}/tier_r_probe_executable"
)
if run_local_capture "tier_r.execute" \
  "tier_r_probe.json" "tier_r_probe.stderr.log" "${tier_argv[@]}"; then
  :
else
  status="$?"
  fail_gate "tier_r.execute" "$status" \
    "real provisional franken-core parser/lowering/interpreter probe failed" \
    "tier_r_probe.json" "tier_r_probe.stderr.log"
fi
tier_command="$(shell_join timeout "$runtime_timeout_seconds" "${tier_argv[@]}")"
if run_local_capture "tier_r.validate" \
  "tier_r_validation_report.json" "tier_r_validation.stderr.log" \
  "$validator_bin" validate-tier-r --probe "${run_dir}/tier_r_probe.json"; then
  :
else
  status="$?"
  fail_gate "tier_r.validate" "$status" "Tier-R report failed structural validation" \
    "tier_r_validation_report.json" "tier_r_validation.stderr.log"
fi
jq -se '
  length == 1
  and (.[0] |
    .status == "pass"
    and .error_count == 0
    and .scenario_count > 0
  )
' "${run_dir}/tier_r_validation_report.json" >/dev/null \
  || fail_gate "tier_r.validate.report" 96 \
    "Tier-R validator did not prove a nonempty passing scenario set" \
    "tier_r_validation_report.json" "tier_r_validation.stderr.log"

probe_executable_sha="$(sha256_file "${run_dir}/tier_r_probe_executable")"
[[ -s "${run_dir}/tier_r_source_manifest.json" \
  && ! -L "${run_dir}/tier_r_source_manifest.json" ]] \
  || fail_gate "tier_r.source_manifest" 97 \
    "Tier-R probe did not publish its build-bound source manifest"
tier_source_manifest_sha="$(sha256_file "${run_dir}/tier_r_source_manifest.json")"
[[ -s "${run_dir}/tier_r_build_environment.json" \
  && ! -L "${run_dir}/tier_r_build_environment.json" ]] \
  || fail_gate "tier_r.build_environment" 97 \
    "Tier-R probe did not publish its embedded build-environment evidence"
tier_build_environment_sha="$(
  sha256_file "${run_dir}/tier_r_build_environment.json"
)"
jq -se --arg digest "$probe_executable_sha" \
  --arg source_manifest_sha "$tier_source_manifest_sha" \
  --arg build_environment_sha "$tier_build_environment_sha" \
  'length == 1
   and (.[0] |
     .schema_version == "franken-engine.provisional-tier-r-probe.v2"
     and .probe_executable_sha256 == $digest
     and .reference_source_sha256 == $source_manifest_sha
     and .build_environment_sha256 == $build_environment_sha
     and .classification == "provisional_not_certified_tier_r"
     and .denial.decision == "deny"
     and .status == "pass"
   )' \
  "${run_dir}/tier_r_probe.json" >/dev/null \
  || fail_gate "tier_r.executable_binding" 97 \
    "Tier-R output is not bound to the retained executable, source closure, build environment, or fail-closed denial probe" \
    "tier_r_probe.json" "tier_r_probe.stderr.log"
if ! jq -e \
  --arg source_manifest_sha "$tier_source_manifest_sha" \
  --arg target "$target" \
  --arg requested_toolchain "$toolchain" \
  --arg builder_identity_sha "$build_worker_sha" \
  '
    .schema_version == "franken-engine.tier-r-build-environment.v1"
    and .source_manifest_sha256 == $source_manifest_sha
    and .target == $target
    and .profile == "release"
    and .opt_level == "3"
    and (
      .requested_toolchain == $requested_toolchain
      or (.requested_toolchain | startswith($requested_toolchain + "-"))
    )
    and (.active_features | index("CARGO_FEATURE_TIER_R_PROBE") != null)
    and .builder_identity_source == "RCH_WORKER_ID"
    and .builder_identity_sha256 == $builder_identity_sha
  ' "${run_dir}/tier_r_build_environment.json" >/dev/null; then
  fail_gate "tier_r.build_environment" 97 \
    "Tier-R build environment does not bind the source closure, target, release profile, toolchain, feature, or admitted builder identity"
fi
append_phase "tier_r.executable_binding" "pass" 0 0 \
  "probe output binds the retained executable, canonical source manifest, embedded build environment, and a real capability denial"

if ! python3 - "${run_dir}/tier_r_source_manifest.json" <<'PY'
import json
import re
import sys

manifest_path = sys.argv[1]
with open(manifest_path, "r", encoding="utf-8") as source:
    manifest = json.load(source)
    if source.read().strip():
        raise SystemExit("Tier-R source manifest contains trailing JSON data")
if set(manifest) != {"schema_version", "hash_algorithm", "identity_basis", "files"}:
    raise SystemExit("Tier-R source manifest has unexpected top-level fields")
if (
    manifest["schema_version"] != "franken-engine.tier-r-source-manifest.v1"
    or manifest["hash_algorithm"] != "sha256"
    or manifest["identity_basis"]
    != "canonical-json-path-bytes-content-sha256-v1"
):
    raise SystemExit("Tier-R source manifest identity contract differs")
files = manifest["files"]
if not isinstance(files, list) or not files or len(files) > 4096:
    raise SystemExit("Tier-R source manifest file count is outside its bound")
paths = []
total_bytes = 0
for entry in files:
    if not isinstance(entry, dict) or set(entry) != {"path", "bytes", "sha256"}:
        raise SystemExit("Tier-R source manifest entry shape differs")
    path = entry["path"]
    size = entry["bytes"]
    digest = entry["sha256"]
    if (
        not isinstance(path, str)
        or not path
        or path.startswith("/")
        or "\\" in path
        or any(ord(character) < 32 or ord(character) == 127 for character in path)
        or any(component in ("", ".", "..") for component in path.split("/"))
        or "/".join(path.split("/")) != path
    ):
        raise SystemExit(f"Tier-R source manifest path is unsafe: {path!r}")
    if type(size) is not int or size < 0 or size > 64 * 1024 * 1024:
        raise SystemExit(f"Tier-R source manifest size is unsafe: {path}")
    if not isinstance(digest, str) or re.fullmatch(r"[0-9a-f]{64}", digest) is None:
        raise SystemExit(f"Tier-R source manifest digest is invalid: {path}")
    paths.append(path)
    total_bytes += size
if paths != sorted(set(paths)):
    raise SystemExit("Tier-R source manifest paths are duplicated or unordered")
if total_bytes > 256 * 1024 * 1024:
    raise SystemExit("Tier-R source closure exceeds 256 MiB")
PY
then
  fail_gate "tier_r.source_manifest_shape" 97 \
    "Tier-R source manifest failed independent path, ordering, size, or digest validation"
fi

declare -a tier_source_artifacts=()
tier_source_root="${run_dir}/tier_r_source"
mkdir "$tier_source_root"
while IFS= read -r -d '' source_path \
  && IFS= read -r -d '' expected_bytes \
  && IFS= read -r -d '' expected_sha; do
  source_absolute="${root_dir}/${source_path}"
  destination_relative="tier_r_source/${source_path}"
  destination_absolute="${run_dir}/${destination_relative}"
  [[ -f "$source_absolute" && ! -L "$source_absolute" ]] \
    || fail_gate "tier_r.source_copy" 97 \
      "manifested Tier-R source is not a regular non-symlink file: ${source_path}"
  [[ ! -e "$destination_absolute" && ! -L "$destination_absolute" ]] \
    || fail_gate "tier_r.source_copy" 97 \
      "refusing to replace retained Tier-R source: ${destination_relative}"
  mkdir -p "${destination_absolute%/*}"
  if ! cp --no-clobber -- "$source_absolute" "$destination_absolute"; then
    fail_gate "tier_r.source_copy" 97 \
      "could not retain manifested Tier-R source: ${source_path}"
  fi
  [[ -f "$destination_absolute" && ! -L "$destination_absolute" ]] \
    || fail_gate "tier_r.source_copy" 97 \
      "retained Tier-R source is not a regular non-symlink file: ${destination_relative}"
  actual_bytes="$(stat -c %s "$destination_absolute")"
  actual_sha="$(sha256_file "$destination_absolute")"
  if [[ "$actual_bytes" != "$expected_bytes" || "$actual_sha" != "$expected_sha" ]]; then
    fail_gate "tier_r.source_copy" 97 \
      "retained Tier-R source bytes or SHA-256 differ: ${destination_relative}"
  fi
  tier_source_artifacts+=("$destination_relative")
done < <(
  jq -j \
    '.files[] | .path, "\u0000", (.bytes | tostring), "\u0000", .sha256, "\u0000"' \
    "${run_dir}/tier_r_source_manifest.json"
)
tier_source_expected_count="$(
  jq -er '.files | length' "${run_dir}/tier_r_source_manifest.json"
)"
if [[ "${#tier_source_artifacts[@]}" -ne "$tier_source_expected_count" ]]; then
  fail_gate "tier_r.source_copy" 97 \
    "retained Tier-R source count differs from its manifest"
fi
unexpected_tier_source_entry="$(
  find "$tier_source_root" -mindepth 1 \
    \( -type l -o \( ! -type d -a ! -type f \) \) -print -quit
)"
[[ -z "$unexpected_tier_source_entry" ]] \
  || fail_gate "tier_r.source_copy" 97 \
    "retained Tier-R source closure contains a non-regular entry: ${unexpected_tier_source_entry}"
mapfile -t actual_tier_source_artifacts < <(
  find "$tier_source_root" -type f -printf 'tier_r_source/%P\n' | LC_ALL=C sort
)
mapfile -t expected_tier_source_artifacts < <(
  printf '%s\n' "${tier_source_artifacts[@]}" | LC_ALL=C sort
)
if [[ "$(printf '%s\n' "${actual_tier_source_artifacts[@]}")" \
  != "$(printf '%s\n' "${expected_tier_source_artifacts[@]}")" ]]; then
  fail_gate "tier_r.source_copy" 97 \
    "retained Tier-R source inventory contains missing, duplicate, or unlisted files"
fi
append_phase "tier_r.source_copy" "pass" 0 0 \
  "retained ${#tier_source_artifacts[@]} exact regular non-symlink Tier-R build inputs bound by byte length and SHA-256"

if [[ "$source_state" == "dirty" ]]; then
  {
    git diff --binary --full-index --no-ext-diff HEAD --
    for untracked_path in "${initial_untracked_files[@]}"; do
      [[ -f "$untracked_path" && ! -L "$untracked_path" ]] \
        || fail_gate "source.diff" 98 \
          "nonignored untracked source is no longer a regular file: ${untracked_path}"
      no_index_status=0
      git diff --binary --full-index --no-ext-diff --no-index \
        /dev/null "./${untracked_path}" || no_index_status="$?"
      if [[ "$no_index_status" -ne 1 ]]; then
        fail_gate "source.diff" 98 \
          "could not encode untracked source in Git binary patch: ${untracked_path}"
      fi
    done
  } >"${run_dir}/source.diff"
  [[ -s "${run_dir}/source.diff" ]] \
    || fail_gate "source.diff" 98 "dirty source state produced an empty source.diff"
  source_diff_sha="$(sha256_file "${run_dir}/source.diff")"
  append_phase "source.diff" "pass" 0 0 \
    "dirty tracked and nonignored untracked regular sources are retained as a Git binary patch"
else
  source_diff_sha=""
  append_phase "source.diff" "pass" 0 0 \
    "clean source state correctly omits source.diff"
fi

rustc_version="$(RUSTUP_TOOLCHAIN="$toolchain" rustc --version)"
cargo_version="$(RUSTUP_TOOLCHAIN="$toolchain" cargo --version)"
jq -n \
  --arg schema_version "franken-engine.verification-environment.v2" \
  --arg platform "$platform" \
  --arg target "$target" \
  --arg tier "$tier" \
  --arg security_profile "$security_profile" \
  --arg rustc_version "$rustc_version" \
  --arg cargo_version "$cargo_version" \
  --arg toolchain "$toolchain" \
  --arg toolchain_role "local_orchestrator" \
  --arg repository_revision "$repository_revision" \
  --arg source_state "$source_state" \
  --arg source_tree_basis "$source_tree_basis" \
  --arg source_identity_command "$source_identity_command" \
  --arg source_tree_sha256 "$initial_source_tree_sha" \
  --arg source_diff_basis "$source_diff_basis" \
  --arg source_diff_sha256 "$source_diff_sha" \
  '{
    schema_version:$schema_version,
    platform:$platform,
    target:$target,
    tier:$tier,
    security_profile:$security_profile,
    rustc_version:$rustc_version,
    cargo_version:$cargo_version,
    toolchain:$toolchain,
    toolchain_role:$toolchain_role,
    repository_revision:$repository_revision,
    source_state:$source_state,
    source_tree_basis:$source_tree_basis,
    source_identity_command:$source_identity_command,
    source_tree_sha256:$source_tree_sha256,
    source_diff_basis:(if $source_state == "dirty" then $source_diff_basis else null end),
    source_diff_sha256:(if $source_state == "dirty" then $source_diff_sha256 else null end)
  }' >"${run_dir}/env.json"

{
  printf '# Legal and Provenance Notice\n\n'
  printf 'This evidence bundle was generated from FrankenEngine repository revision %s.\n\n' \
    "$repository_revision"
  printf 'It contains RCH coordinator-reported build outputs for the validator and provisional Tier-R probe, copied and hashed immediately after retrieval, and redistributes no external JavaScript corpus.\n'
  printf 'The retained RCH diagnostics prove admission to an eligible worker only; successful build and test phases remain coordinator-observed and unattested rather than cryptographic worker-completion receipts.\n'
  printf 'The probe is evidence for a real franken-core reference execution lane; it is explicitly not a certified Tier-R graduation claim.\n'
} >"${run_dir}/LEGAL.md"

final_source_tree_sha="$(./scripts/run_verification_coverage_contract_gate.sh source-identity)"
record_command "$source_identity_command"
final_source_status="$(git status --porcelain=v1 --untracked-files=all)"
final_repository_revision="$(git rev-parse HEAD)"
if [[ "$final_source_tree_sha" != "$initial_source_tree_sha" \
  || "$final_source_status" != "$source_status" \
  || "$final_repository_revision" != "$repository_revision" ]]; then
  fail_gate "source.identity.final" 99 \
    "source closure, Git status, or repository revision changed during the certifying run"
fi
append_phase "source.identity.final" "pass" 0 0 \
  "source closure remained byte- and mode-identical throughout the run"

if [[ "$(sha256_file "$built_validator_bin")" != "$built_validator_sha" \
  || "$(sha256_file "$built_probe_bin")" != "$built_probe_sha" \
  || "$(sha256_file "$validator_bin")" != "$built_validator_sha" \
  || "$(sha256_file "$probe_bin")" != "$built_probe_sha" ]]; then
  fail_gate "tool.artifact_final_rehash" 88 \
    "a retained or coordinator-retrieved executable changed before publication"
fi
append_phase "tool.artifact_final_rehash" "pass" 0 0 \
  "both retained executables still match their immediate post-build SHA-256 identities"

if [[ "$(sha256_file "$contract_source")" != "$canonical_contract_before" \
  || "$(sha256_file "$markdown_source")" != "$canonical_markdown_before" ]]; then
  fail_gate "rollback.verify" 100 \
    "a committed canonical input changed during the read-only gate"
fi
if [[ -n "$(jobs -p)" ]]; then
  fail_gate "cleanup.verify" 101 \
    "gate would publish while child processes remain active"
fi
append_phase "cleanup.verify" "pass" 0 0 \
  "no child process remains and no committed input was changed; rollback is the unchanged prior canonical pair"

artifact_manifest_command="$(shell_join timeout "$runtime_timeout_seconds" \
  "$validator_bin" artifact-manifest --bundle "$run_dir")"
bundle_validation_command="$(shell_join timeout "$runtime_timeout_seconds" \
  "$validator_bin" validate-bundle --bundle "$run_dir")"
record_command "$artifact_manifest_command"
record_command "$bundle_validation_command"

for command_line in "${recorded_commands[@]}"; do
  printf '%s\n' "$command_line"
done >"${run_dir}/commands.txt"

reproduction_stdout_sha="$(sha256_file "${run_dir}/reproduction.stdout.log")"
reproduction_stderr_sha="$(sha256_file "${run_dir}/reproduction.stderr.log")"
jq -n \
  --arg schema_version "franken-engine.verification-reproduction-record.v1" \
  --arg command "$reproduction_command" \
  --arg executed_at_utc "$reproduction_started_at" \
  --arg stdout_sha256 "$reproduction_stdout_sha" \
  --arg stderr_sha256 "$reproduction_stderr_sha" \
  '{
    schema_version:$schema_version,
    command:$command,
    executed_at_utc:$executed_at_utc,
    exit_code:0,
    stdout_path:"reproduction.stdout.log",
    stdout_sha256:$stdout_sha256,
    stderr_path:"reproduction.stderr.log",
    stderr_sha256:$stderr_sha256,
    cleanup_complete:true,
    rollback_verified:true
  }' >"${run_dir}/reproduction_record.json"

tier_stdout_sha="$(sha256_file "${run_dir}/tier_r_probe.json")"
tier_stderr_sha="$(sha256_file "${run_dir}/tier_r_probe.stderr.log")"
jq -n \
  --arg schema_version "franken-engine.tier-r-invocation.v1" \
  --arg command "$tier_command" \
  --arg executed_at_utc "$tier_started_at" \
  --arg stdout_sha256 "$tier_stdout_sha" \
  --arg stderr_sha256 "$tier_stderr_sha" \
  --arg executable_sha256 "$probe_executable_sha" \
  '{
    schema_version:$schema_version,
    command:$command,
    executed_at_utc:$executed_at_utc,
    exit_code:0,
    stdout_path:"tier_r_probe.json",
    stdout_sha256:$stdout_sha256,
    stderr_path:"tier_r_probe.stderr.log",
    stderr_sha256:$stderr_sha256,
    executable_path:"tier_r_probe_executable",
    executable_sha256:$executable_sha256
  }' >"${run_dir}/tier_r_invocation.json"

validation_report_sha="$(sha256_file "${run_dir}/validation_report.json")"
sample_duration_ns="$(jq '[.events[].duration_ns] | add // 0' \
  "${run_dir}/reproduction.stdout.log")"
jq -nc \
  --arg schema_version "franken-engine.verification-sample.v1" \
  --arg sample_id "${run_id}:canonical" \
  --argjson seed "$seed" \
  --argjson duration_ns "$sample_duration_ns" \
  --arg validation_report_sha "$validation_report_sha" \
  '{
    schema_version:$schema_version,
    sample_id:$sample_id,
    seed:$seed,
    outcome:"pass",
    duration_ns:$duration_ns,
    artifact_hashes:{"validation_report.json":$validation_report_sha}
  }' >"${run_dir}/samples.jsonl"

contract_sha="$(sha256_file "${run_dir}/contract.json")"
generated_contract_sha="$(sha256_file "${run_dir}/generated_contract.json")"
commands_sha="$(sha256_file "${run_dir}/commands.txt")"
tier_source_sha="$(jq -r '.reference_source_sha256' "${run_dir}/tier_r_probe.json")"
jq -n \
  --arg schema_version "franken-engine.verification-repro-lock.v1" \
  --arg source_tree_sha256 "$initial_source_tree_sha" \
  --arg cargo_lock_sha256 "$(sha256_file "${run_dir}/root.Cargo.lock")" \
  --arg tool_lock_sha256 "$(sha256_file "${run_dir}/tool.Cargo.lock")" \
  --arg contract_sha256 "$contract_sha" \
  --arg generated_contract_sha256 "$generated_contract_sha" \
  --arg commands_sha256 "$commands_sha" \
  --arg tier_r_source_sha256 "$tier_source_sha" \
  --arg tier_r_build_environment_sha256 "$tier_build_environment_sha" \
  '{
    schema_version:$schema_version,
    source_tree_sha256:$source_tree_sha256,
    cargo_lock_sha256:$cargo_lock_sha256,
    tool_lock_sha256:$tool_lock_sha256,
    contract_sha256:$contract_sha256,
    generated_contract_sha256:$generated_contract_sha256,
    commands_sha256:$commands_sha256,
    tier_r_source_sha256:$tier_r_source_sha256,
    tier_r_build_environment_sha256:$tier_r_build_environment_sha256
  }' >"${run_dir}/repro.lock"

append_phase "publication.prepare" "pass" 0 0 \
  "all mutable evidence is frozen; provenance and manifest publication follow without replacement"

declare -a required_files=(
  LEGAL.md
  artifact_manifest.json
  build.rch_diagnose.json
  build.rch_diagnose.stderr.log
  build.stderr.log
  build.stdout.log
  commands.txt
  contract.json
  env.json
  event_validation.stderr.log
  event_validation_report.json
  events.jsonl
  generate.stderr.log
  generated_contract.json
  guest.stderr.log
  guest.stdout.log
  phase_events.jsonl
  provenance_graph.json
  render.stderr.log
  rendered_contract.md
  replay.stderr.log
  replay.stdout.log
  repro.lock
  reproduction.stderr.log
  reproduction.stdout.log
  reproduction_record.json
  root.Cargo.lock
  run_manifest.json
  samples.jsonl
  tests.stderr.log
  tests.stdout.log
  tests.rch_diagnose.json
  tests.rch_diagnose.stderr.log
  tier_r_build_environment.json
  tier_r_invocation.json
  tier_r_probe.json
  tier_r_probe.stderr.log
  tier_r_probe_executable
  tier_r_source_manifest.json
  tier_r_validation.stderr.log
  tier_r_validation_report.json
  tool.Cargo.lock
  validation_report.json
  verification_coverage_contract_validator
)
if [[ "$source_state" == "dirty" ]]; then
  required_files+=(source.diff)
fi
required_files+=("${tier_source_artifacts[@]}")
mapfile -t required_files < <(printf '%s\n' "${required_files[@]}" | LC_ALL=C sort)
required_files_json="$(printf '%s\n' "${required_files[@]}" \
  | jq -Rsc 'split("\n")[:-1]')"

jq -n \
  --arg schema_version "franken-engine.verification-run-manifest.v2" \
  --arg run_id "$run_id" \
  --arg trace_id "$trace_id" \
  --arg test_id "$test_id" \
  --arg scenario_id "$scenario_id" \
  --argjson seed "$seed" \
  --argjson attempt "$attempt" \
  --arg platform "$platform" \
  --arg target "$target" \
  --arg tier "$tier" \
  --arg security_profile "$security_profile" \
  --arg created_at_utc "$created_at_utc" \
  --arg reproduction_command "$reproduction_command" \
  --argjson required_files "$required_files_json" \
  '{
    schema_version:$schema_version,
    run_id:$run_id,
    trace_id:$trace_id,
    test_id:$test_id,
    scenario_id:$scenario_id,
    seed:$seed,
    attempt:$attempt,
    platform:$platform,
    target:$target,
    tier:$tier,
    security_profile:$security_profile,
    created_at_utc:$created_at_utc,
    clock_source:"witnessed_wall_clock",
    expected_outcome:"pass",
    observed_outcome:"pass",
    exit_code:0,
    first_failure:null,
    reproduction_command:$reproduction_command,
    artifact_manifest:"artifact_manifest.json",
    contract:"contract.json",
    generated_contract:"generated_contract.json",
    rendered_markdown:"rendered_contract.md",
    validation_report:"validation_report.json",
    events:"events.jsonl",
    tier_r_probe:"tier_r_probe.json",
    tier_r_source_manifest:"tier_r_source_manifest.json",
    tier_r_build_environment:"tier_r_build_environment.json",
    sample_artifact:{kind:"raw_samples",path:"samples.jsonl"},
    required_files:$required_files,
    guest_stdout:"guest.stdout.log",
    guest_stderr:"guest.stderr.log"
  }' >"${run_dir}/run_manifest.json"

declare -a provenance_paths=()
for artifact_path in "${required_files[@]}"; do
  case "$artifact_path" in
    artifact_manifest.json | provenance_graph.json) ;;
    *) provenance_paths+=("$artifact_path") ;;
  esac
done

nodes_json="$(
  {
    jq -nc --arg sha "$contract_sha" \
      '{node_id:"requirement:verification-coverage-contract",kind:"requirement",sha256:$sha,artifact_path:null}'
    for artifact_path in "${provenance_paths[@]}"; do
      node_kind="artifact"
      case "$artifact_path" in
        run_manifest.json) node_kind="run" ;;
        events.jsonl) node_kind="event_stream" ;;
        validation_report.json) node_kind="verdict" ;;
      esac
      jq -nc \
        --arg node_id "artifact:${artifact_path}" \
        --arg kind "$node_kind" \
        --arg sha "$(sha256_file "${run_dir}/${artifact_path}")" \
        --arg artifact_path "$artifact_path" \
        '{node_id:$node_id,kind:$kind,sha256:$sha,artifact_path:$artifact_path}'
    done
  } | jq -s .
)"
edges_json="$(
  {
    jq -nc \
      '{from:"requirement:verification-coverage-contract",relation:"governs",to:"artifact:run_manifest.json"}'
    for artifact_path in "${provenance_paths[@]}"; do
      case "$artifact_path" in
        run_manifest.json) ;;
        validation_report.json)
          jq -nc \
            '{from:"artifact:run_manifest.json",relation:"produces",to:"artifact:validation_report.json"}'
          ;;
        *)
          jq -nc --arg to "artifact:${artifact_path}" \
            '{from:"artifact:run_manifest.json",relation:"retains",to:$to}'
          jq -nc --arg from "artifact:${artifact_path}" \
            '{from:$from,relation:"supports",to:"artifact:validation_report.json"}'
          ;;
      esac
    done
  } | jq -s .
)"
jq -n \
  --arg schema_version "franken-engine.verification-provenance-graph.v1" \
  --argjson nodes "$nodes_json" \
  --argjson edges "$edges_json" \
  '{schema_version:$schema_version,nodes:$nodes,edges:$edges}' \
  >"${run_dir}/provenance_graph.json"

unexpected_bundle_entry="$(
  find "$run_dir" -mindepth 1 \
    \( -type l -o \( ! -type d -a ! -type f \) \) -print -quit
)"
[[ -z "$unexpected_bundle_entry" ]] \
  || fail_gate "publication.regular_files" 103 \
    "bundle contains a symlink or non-regular entry: ${unexpected_bundle_entry}"
mapfile -t actual_before_manifest < <(
  find "$run_dir" -mindepth 1 -type f -printf '%P\n' | LC_ALL=C sort
)
declare -a expected_before_manifest=()
for artifact_path in "${required_files[@]}"; do
  [[ "$artifact_path" == "artifact_manifest.json" ]] \
    || expected_before_manifest+=("$artifact_path")
done
if [[ "$(printf '%s\n' "${actual_before_manifest[@]}")" \
  != "$(printf '%s\n' "${expected_before_manifest[@]}")" ]]; then
  fail_gate "publication.inventory" 102 \
    "pre-manifest bundle inventory differs from run_manifest.required_files"
fi

total_bytes=0
for artifact_path in "${actual_before_manifest[@]}"; do
  absolute_artifact="${run_dir}/${artifact_path}"
  [[ -f "$absolute_artifact" && ! -L "$absolute_artifact" ]] \
    || fail_gate "publication.regular_files" 103 \
      "bundle member is not a regular non-symlink file: ${artifact_path}"
  artifact_bytes="$(stat -c %s "$absolute_artifact")"
  if (( artifact_bytes > 64 * 1024 * 1024 )); then
    fail_gate "publication.bounds" 104 \
      "bundle member exceeds 64 MiB: ${artifact_path}"
  fi
  total_bytes=$((total_bytes + artifact_bytes))
done
if (( total_bytes > 256 * 1024 * 1024 )); then
  fail_gate "publication.bounds" 104 \
    "pre-manifest bundle exceeds 256 MiB"
fi

set +e
manifest_stdout="$(timeout "$runtime_timeout_seconds" \
  "$validator_bin" artifact-manifest --bundle "$run_dir" 2>&1)"
manifest_status="$?"
set -e
if [[ "$manifest_status" -ne 0 ]]; then
  fail_gate "publication.manifest" "$manifest_status" \
    "no-replace artifact manifest publication failed"
fi
manifest_published=true
printf '%s\n' "$manifest_stdout" | jq -se \
  'length == 1
   and (.[0] |
     .schema_version == "franken-engine.verification-artifact-manifest.v1"
     and .hash_algorithm == "sha256"
     and (.files | length > 0)
   )' >/dev/null \
  || {
    echo "published artifact manifest stdout was malformed" >&2
    exit 105
  }

set +e
bundle_report="$(timeout "$runtime_timeout_seconds" \
  "$validator_bin" validate-bundle --bundle "$run_dir" 2>&1)"
bundle_status="$?"
set -e
if [[ "$bundle_status" -ne 0 ]] \
  || ! printf '%s\n' "$bundle_report" | jq -se \
    'length == 1
     and (.[0] |
       .status == "pass"
       and .error_count == 0
       and .checked_files > 0
       and .event_count > 1
     )' \
    >/dev/null; then
  echo "$bundle_report" >&2
  echo "published bundle failed strict post-publication validation" >&2
  echo "recoverable_run_dir=${run_dir}" >&2
  exit 106
fi

echo "verification_coverage_contract_run_dir=${run_dir}"
echo "verification_coverage_contract_manifest=${run_dir}/artifact_manifest.json"
echo "verification_coverage_contract_validator=${validator_bin}"
echo "verification_coverage_contract_probe=${run_dir}/tier_r_probe_executable"
echo "verification_coverage_contract_verdict=pass"
