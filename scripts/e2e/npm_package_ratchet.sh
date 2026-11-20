#!/usr/bin/env bash
# bd-9vouw.62: Engine-level differential ratchet over vendored real npm packages.
#
# Runs every vendored package under crates/franken-engine/tests/fixtures/npm_packages/
# through frankenctl run (and live node when available), comparing against the
# recorded Node v22.2.0 outputs. Writes exact commands, exit codes, first failure
# class, output diffs, results.jsonl, and summary.json into a timestamped artifact
# directory outside the repository worktree (never deletes files).
#
# Usage:
#   scripts/e2e/npm_package_ratchet.sh [artifact_dir]
#
# Optional environment variables:
#   FRANKENCTL_BIN           Path to a prebuilt frankenctl binary. When unset, the
#                            script looks for an existing target binary or runs
#                            the Rust integration ratchet test via rch/cargo.
#   NPM_RATCHET_ARTIFACT_DIR Default artifact root when no positional arg is given.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"
FIXTURE_ROOT="${REPO_ROOT}/crates/franken-engine/tests/fixtures/npm_packages"
TIMESTAMP="$(date -u +%Y%m%dT%H%M%SZ)"
DEFAULT_ROOT="${NPM_RATCHET_ARTIFACT_DIR:-${XDG_CACHE_HOME:-${HOME}/.cache}/franken_engine/npm_package_ratchet}"
ARTIFACT_DIR="${1:-${DEFAULT_ROOT}/${TIMESTAMP}}"

mkdir -p "${ARTIFACT_DIR}"
COMMANDS_LOG="${ARTIFACT_DIR}/commands.txt"
RESULTS_JSONL="${ARTIFACT_DIR}/results.jsonl"
SUMMARY_JSON="${ARTIFACT_DIR}/summary.json"
: > "${COMMANDS_LOG}"
: > "${RESULTS_JSONL}"

resolve_frankenctl() {
  if [[ -n "${FRANKENCTL_BIN:-}" && -x "${FRANKENCTL_BIN}" ]]; then
    printf '%s\n' "${FRANKENCTL_BIN}"
    return 0
  fi
  for candidate in \
    "${REPO_ROOT}/target/release/frankenctl" \
    "${REPO_ROOT}/target/debug/frankenctl" \
    "${CARGO_TARGET_DIR:-}/release/frankenctl" \
    "${CARGO_TARGET_DIR:-}/debug/frankenctl"; do
    if [[ -n "${candidate}" && -x "${candidate}" ]]; then
      printf '%s\n' "${candidate}"
      return 0
    fi
  done
  if command -v frankenctl >/dev/null 2>&1; then
    command -v frankenctl
    return 0
  fi
  return 1
}

classify_failure() {
  local stderr_file="$1"
  local stderr_text
  stderr_text="$(cat "${stderr_file}" 2>/dev/null || true)"
  if printf '%s' "${stderr_text}" | grep -qiE 'parse:|InvalidSyntax|UnsupportedSyntax|EmptySource|token budget'; then
    printf 'parse\n'
  elif printf '%s' "${stderr_text}" | grep -qiE 'lower|UnauthorizedFlow|AmbientAuthority|requires effect'; then
    printf 'lowering\n'
  elif printf '%s' "${stderr_text}" | grep -qiE 'interpreter|TypeError|ReferenceError|RangeError|SyntaxError|budget'; then
    printf 'runtime\n'
  else
    printf 'execution_error\n'
  fi
}

BIN_PATH=""
if BIN_PATH="$(resolve_frankenctl)"; then
  echo "Using frankenctl binary: ${BIN_PATH}"
else
  echo "No local frankenctl binary found; invoking integration ratchet test via rch/cargo."
  if command -v rch >/dev/null 2>&1; then
    CMD=(rch exec -- cargo test -j 2 -p frankenengine-engine --test npm_package_ratchet_bd_9vouw_62)
  else
    CMD=(cargo test -j 2 -p frankenengine-engine --test npm_package_ratchet_bd_9vouw_62)
  fi
  printf '%q ' "${CMD[@]}" >> "${COMMANDS_LOG}"
  printf '\n' >> "${COMMANDS_LOG}"
  set +e
  "${CMD[@]}" > "${ARTIFACT_DIR}/cargo_ratchet.stdout" 2> "${ARTIFACT_DIR}/cargo_ratchet.stderr"
  RC=$?
  set -e
  python3 - "${RESULTS_JSONL}" "${SUMMARY_JSON}" "${ARTIFACT_DIR}" "${RC}" <<'PY'
import json, sys
results_path, summary_path, artifact_dir, rc = sys.argv[1], sys.argv[2], sys.argv[3], int(sys.argv[4])
entry = {
    "mode": "cargo_integration_test",
    "test_target": "npm_package_ratchet_bd_9vouw_62",
    "packages": ["ms", "minimist", "dayjs"],
    "exit_code": rc,
    "first_failure_class": "none" if rc == 0 else "test_failure",
    "status": "pass" if rc == 0 else "fail",
}
with open(results_path, "a", encoding="utf-8") as fh:
    fh.write(json.dumps(entry) + "\n")
summary = {
    "schema_version": "franken-engine.npm-package-ratchet.v1",
    "artifact_dir": artifact_dir,
    "mode": "cargo_integration_test",
    "total": 3,
    "passed": 3 if rc == 0 else 0,
    "failed": 0 if rc == 0 else 3,
    "exit_code": rc,
    "verdict": "pass" if rc == 0 else "fail",
}
with open(summary_path, "w", encoding="utf-8") as fh:
    json.dump(summary, fh, indent=2)
    fh.write("\n")
PY
  cat "${ARTIFACT_DIR}/cargo_ratchet.stdout"
  if [[ "${RC}" -ne 0 ]]; then
    cat "${ARTIFACT_DIR}/cargo_ratchet.stderr" >&2
  fi
  echo "Artifacts written to: ${ARTIFACT_DIR}"
  exit "${RC}"
fi

PACKAGE_NAMES=("ms" "minimist" "dayjs")
PACKAGE_FILES=("ms-2.1.3/index.js" "minimist-1.2.8/index.js" "dayjs-1.11.13/dayjs.min.js")
PACKAGE_USAGES=(
  "console.log(m('2 days'), m('1h'), m(60000), m(2 * 60000, { long: true }), m('-3.5s'));"
  "const a = m(['-x', '3', '-y4', '-n5', '-abc', '--beep=boop', 'foo', 'bar', '--no-z']); console.log(JSON.stringify(a));"
  "const d = m('2020-01-31T12:00:00Z'); console.log(d.valueOf(), d.add(1, 'day').toISOString(), d.isValid(), m('invalid').isValid());"
)
PACKAGE_EXPECTED=(
  "172800000 3600000 1m 2 minutes -3500"
  '{"_":["foo","bar"],"x":3,"y":4,"n":5,"a":true,"b":true,"c":true,"beep":"boop","z":false}'
  "1580472000000 2020-02-01T12:00:00.000Z true false"
)

PASS_COUNT=0
FAIL_COUNT=0
NODE_BIN="$(command -v node || true)"

for idx in "${!PACKAGE_NAMES[@]}"; do
  name="${PACKAGE_NAMES[$idx]}"
  rel_file="${PACKAGE_FILES[$idx]}"
  usage="${PACKAGE_USAGES[$idx]}"
  expected="${PACKAGE_EXPECTED[$idx]}"
  src_path="${FIXTURE_ROOT}/${rel_file}"
  wrapped="${ARTIFACT_DIR}/${name}.wrapped.js"
  report="${ARTIFACT_DIR}/${name}.run.json"
  fe_stdout="${ARTIFACT_DIR}/${name}.frankenctl.stdout"
  fe_stderr="${ARTIFACT_DIR}/${name}.frankenctl.stderr"
  actual_txt="${ARTIFACT_DIR}/${name}.actual.txt"
  expected_txt="${ARTIFACT_DIR}/${name}.expected.txt"
  diff_txt="${ARTIFACT_DIR}/${name}.diff"

  {
    printf 'var module = { exports: {} }; var exports = module.exports;\n'
    printf '(function (module, exports) {\n'
    cat "${src_path}"
    printf '\n})(module, exports);\n'
    printf 'var m = module.exports;\n%s\n' "${usage}"
  } > "${wrapped}"
  printf '%s\n' "${expected}" > "${expected_txt}"

  CMD=(
    "${BIN_PATH}" run
    --input "${wrapped}"
    --extension-id "npm-ratchet-${name}"
    --instruction-budget 100000000
    --out "${report}"
  )
  printf '%q ' "${CMD[@]}" >> "${COMMANDS_LOG}"
  printf '\n' >> "${COMMANDS_LOG}"

  set +e
  "${CMD[@]}" > "${fe_stdout}" 2> "${fe_stderr}"
  RC=$?
  set -e

  node_live_match="skipped"
  if [[ -n "${NODE_BIN}" ]]; then
    node_out="${ARTIFACT_DIR}/${name}.node.stdout"
    if "${NODE_BIN}" "${wrapped}" > "${node_out}" 2> "${ARTIFACT_DIR}/${name}.node.stderr"; then
      if diff -u "${expected_txt}" "${node_out}" > "${ARTIFACT_DIR}/${name}.node.diff"; then
        node_live_match="match"
      else
        node_live_match="drift"
      fi
    else
      node_live_match="error"
    fi
  fi

  first_failure_class="none"
  status="pass"
  if [[ "${RC}" -ne 0 ]]; then
    status="fail"
    first_failure_class="$(classify_failure "${fe_stderr}")"
    : > "${actual_txt}"
    diff -u "${expected_txt}" "${actual_txt}" > "${diff_txt}" || true
    FAIL_COUNT=$((FAIL_COUNT + 1))
  else
    python3 - "${report}" "${actual_txt}" <<'PY'
import json, sys
report_path, actual_path = sys.argv[1], sys.argv[2]
with open(report_path, "r", encoding="utf-8") as fh:
    data = json.load(fh)
lines = [entry["message"] for entry in data.get("console_output", [])]
with open(actual_path, "w", encoding="utf-8") as fh:
    fh.write("\n".join(lines) + "\n")
PY
    if diff -u "${expected_txt}" "${actual_txt}" > "${diff_txt}"; then
      PASS_COUNT=$((PASS_COUNT + 1))
    else
      status="fail"
      first_failure_class="output_mismatch"
      FAIL_COUNT=$((FAIL_COUNT + 1))
    fi
  fi

  python3 - "${RESULTS_JSONL}" "${name}" "${rel_file}" "${RC}" "${status}" "${first_failure_class}" "${node_live_match}" "${diff_txt}" <<'PY'
import json, sys
results_path, name, rel_file, rc, status, failure_class, node_live, diff_path = sys.argv[1:9]
entry = {
    "package": name,
    "fixture": rel_file,
    "exit_code": int(rc),
    "status": status,
    "first_failure_class": failure_class,
    "live_node_check": node_live,
    "diff_path": diff_path,
}
with open(results_path, "a", encoding="utf-8") as fh:
    fh.write(json.dumps(entry) + "\n")
PY
  echo "[${status^^}] ${name} (exit=${RC}, failure_class=${first_failure_class}, live_node=${node_live_match})"
done

TOTAL_COUNT="${#PACKAGE_NAMES[@]}"
VERDICT="pass"
EXIT_STATUS=0
if [[ "${FAIL_COUNT}" -ne 0 ]]; then
  VERDICT="fail"
  EXIT_STATUS=1
fi

python3 - "${SUMMARY_JSON}" "${ARTIFACT_DIR}" "${BIN_PATH}" "${TOTAL_COUNT}" "${PASS_COUNT}" "${FAIL_COUNT}" "${VERDICT}" <<'PY'
import json, sys
summary_path, artifact_dir, bin_path, total, passed, failed, verdict = sys.argv[1:8]
summary = {
    "schema_version": "franken-engine.npm-package-ratchet.v1",
    "artifact_dir": artifact_dir,
    "mode": "frankenctl_direct",
    "frankenctl_bin": bin_path,
    "total": int(total),
    "passed": int(passed),
    "failed": int(failed),
    "verdict": verdict,
}
with open(summary_path, "w", encoding="utf-8") as fh:
    json.dump(summary, fh, indent=2)
    fh.write("\n")
PY

echo "Summary: ${PASS_COUNT}/${TOTAL_COUNT} passed (${VERDICT}); artifacts in ${ARTIFACT_DIR}"
exit "${EXIT_STATUS}"
