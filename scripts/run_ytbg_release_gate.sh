#!/usr/bin/env bash
set -euo pipefail

# bd-8enww.5.7 (YTBG-E7): final YouTube cipher / n-param / BotGuard / PO-token
# release gate.
#
# ONE command runs the full YTBG validation matrix (the focused conformance and
# fixture suites that, together, are the "done" definition for BotGuard / PO-token
# readiness) and writes a self-describing artifact bundle:
#
#   artifacts/ytbg_release_gate/<run_id>/
#     run_manifest.json     schema, run id, git commit, toolchain, per-lane verdicts,
#                           optional-fixture status, overall outcome, artifact hashes
#     commands.txt          every command the gate ran, in order
#     vector_results.jsonl  one JSON record per lane (target, category, required,
#                           status, passed/failed/ignored vector counts, duration)
#     summary.md            human-readable pass/fail table + optional-fixture note
#     logs/<lane>.log       raw test output per lane (carries the per-vector JSON reports)
#
# Exit codes:
#   0  every REQUIRED lane is green (optional franken_whisper fixtures may be absent)
#   2  setup/usage error (missing tool, bad argument)
#   3  a required lane regressed (a vector failed, or a target failed to build/run)
#
# Optional franken_whisper fixtures are reported DISTINCTLY from failures: if
# FRANKEN_ENGINE_POTOKEN_FIXTURES / FRANKEN_ENGINE_YOUTUBE_FIXTURES are unset, the
# supplied-fixture lanes still pass via their structured-skip path, and the manifest
# records `supplied=false` for them — an absent optional fixture never fails the gate.
#
# Environment overrides:
#   YTBG_ARTIFACT_ROOT   artifact root            (default: <repo>/artifacts/ytbg_release_gate)
#   YTBG_RUN_ID          run id / bundle dir name (default: UTC timestamp)
#   CARGO_TARGET_DIR     cargo target dir         (default: /tmp/ytbg_release_gate_target)
#   RUSTUP_TOOLCHAIN     toolchain                (default: nightly-x86_64-unknown-linux-gnu)
#   CARGO_BIN            cargo binary             (default: cargo)
#   YTBG_JOBS            cargo -j value           (default: 24)

usage() {
  cat >&2 <<USAGE
Usage: $0 [ci|run]
  ci   run the full matrix, write artifacts, exit non-zero on any required-lane regression
  run  alias for ci
Environment overrides: YTBG_ARTIFACT_ROOT, YTBG_RUN_ID, CARGO_TARGET_DIR,
RUSTUP_TOOLCHAIN, CARGO_BIN, YTBG_JOBS, FRANKEN_ENGINE_POTOKEN_FIXTURES,
FRANKEN_ENGINE_YOUTUBE_FIXTURES.
USAGE
}

MODE="${1:-ci}"
case "${MODE}" in
  ci | run) ;;
  -h | --help)
    usage
    exit 0
    ;;
  *)
    echo "unknown mode: ${MODE}" >&2
    usage
    exit 2
    ;;
esac

require_tool() {
  if ! command -v "$1" >/dev/null 2>&1; then
    echo "[ytbg-gate] required tool not found: $1" >&2
    exit 2
  fi
}
require_tool python3

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
ARTIFACT_ROOT="${YTBG_ARTIFACT_ROOT:-${REPO_ROOT}/artifacts/ytbg_release_gate}"
RUN_ID="${YTBG_RUN_ID:-$(date -u +%Y%m%dT%H%M%SZ)}"
RUN_DIR="${ARTIFACT_ROOT}/${RUN_ID}"
LOG_DIR="${RUN_DIR}/logs"
TARGET_DIR="${CARGO_TARGET_DIR:-/tmp/ytbg_release_gate_target}"
TOOLCHAIN="${RUSTUP_TOOLCHAIN:-nightly-x86_64-unknown-linux-gnu}"
CARGO="${CARGO_BIN:-cargo}"
JOBS="${YTBG_JOBS:-24}"
PKG="frankenengine-engine"

mkdir -p "${LOG_DIR}"
MANIFEST="${RUN_DIR}/run_manifest.json"
COMMANDS="${RUN_DIR}/commands.txt"
VECTORS="${RUN_DIR}/vector_results.jsonl"
SUMMARY="${RUN_DIR}/summary.md"
: >"${COMMANDS}"
: >"${VECTORS}"

GIT_COMMIT="$(git -C "${REPO_ROOT}" rev-parse HEAD 2>/dev/null || echo unknown)"
GENERATED_AT="$(date -u +%Y-%m-%dT%H:%M:%SZ)"

# Optional franken_whisper fixtures (absent != failure).
POTOKEN_SUPPLIED=false
[ -n "${FRANKEN_ENGINE_POTOKEN_FIXTURES:-}" ] && POTOKEN_SUPPLIED=true
YOUTUBE_SUPPLIED=false
[ -n "${FRANKEN_ENGINE_YOUTUBE_FIXTURES:-}" ] && YOUTUBE_SUPPLIED=true

echo "[ytbg-gate] run_id=${RUN_ID} commit=${GIT_COMMIT}"
echo "[ytbg-gate] artifacts -> ${RUN_DIR}"
echo "[ytbg-gate] target_dir=${TARGET_DIR} toolchain=${TOOLCHAIN}"
echo "[ytbg-gate] franken_whisper fixtures: po_token supplied=${POTOKEN_SUPPLIED} youtube supplied=${YOUTUBE_SUPPLIED}"

# The YTBG validation matrix: lane | test target | category | required(true/false)
# A lane is one focused suite that proves a slice of BotGuard / PO-token readiness.
LANES=(
  "cipher_typedarray_function|youtube_botguard_js_conformance|cipher_n_param_typed_array_function_spike|true"
  "function_constructor|function_constructor_conformance_bd_8enww_3_5|function_constructor|true"
  "exceptions_structured|exception_conformance_suite_bd_8enww_4_6|exception_handling|true"
  "exception_semantics|exception_semantics_conformance|exception_handling|true"
  "synthetic_botguard_vm|botguard_synthetic_vm_smoke_bd_8enww_5_1|synthetic_botguard|true"
  "instruction_budget|botguard_instruction_budget_bd_8enww_5_5|budget_logging|true"
  "po_token_fixture|botguard_potoken_fixture_bd_8enww_5_6|po_token_fixture|true"
)

OVERALL_OK=true
LANE_FACTS="${RUN_DIR}/.lane_facts.tsv"
: >"${LANE_FACTS}"

run_lane() {
  local lane="$1" target="$2" category="$3" required="$4"
  local log="${LOG_DIR}/${lane}.log"
  local cmd=("${CARGO}" test -p "${PKG}" --test "${target}" -j "${JOBS}" -- --nocapture)
  echo "[ytbg-gate] lane=${lane} target=${target} (required=${required})"
  echo "RUSTUP_TOOLCHAIN=${TOOLCHAIN} CARGO_TARGET_DIR=${TARGET_DIR} ${cmd[*]}" >>"${COMMANDS}"

  local started ended duration exit_code=0
  started="$(date +%s)"
  if RUSTUP_TOOLCHAIN="${TOOLCHAIN}" RUSTUP_AUTO_INSTALL=0 CARGO_TARGET_DIR="${TARGET_DIR}" \
    "${cmd[@]}" >"${log}" 2>&1; then
    exit_code=0
  else
    exit_code=$?
  fi
  ended="$(date +%s)"
  duration=$((ended - started))

  # Parse the cargo test summary line. A target may emit several "test result:"
  # lines (one per test binary section); sum them.
  local passed failed ignored status
  passed="$(grep -oE 'test result: [a-zA-Z]+\. [0-9]+ passed' "${log}" | grep -oE '[0-9]+ passed' | grep -oE '[0-9]+' | paste -sd+ - | bc 2>/dev/null || echo 0)"
  failed="$(grep -oE '[0-9]+ failed' "${log}" | grep -oE '[0-9]+' | paste -sd+ - | bc 2>/dev/null || echo 0)"
  ignored="$(grep -oE '[0-9]+ ignored' "${log}" | grep -oE '[0-9]+' | paste -sd+ - | bc 2>/dev/null || echo 0)"
  passed="${passed:-0}"
  failed="${failed:-0}"
  ignored="${ignored:-0}"

  if [ "${exit_code}" -eq 0 ] && [ "${failed}" -eq 0 ]; then
    status="pass"
  elif [ "${failed}" -gt 0 ]; then
    # A compiled-and-run vector regressed. Checked before the build-error pattern
    # because cargo prints "error: test failed" for a runtime failure too.
    status="fail"
  elif grep -qiE "error\[|could not compile|^error:" "${log}"; then
    # A compile error, a missing target, or another cargo error (reached only when
    # no vector reported failed, so this never mislabels a runtime test failure).
    status="build_error"
  else
    status="fail"
  fi

  if [ "${status}" != "pass" ] && [ "${required}" = "true" ]; then
    OVERALL_OK=false
  fi

  printf '%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n' \
    "${lane}" "${target}" "${category}" "${required}" "${status}" \
    "${passed}" "${failed}" "${ignored}" "${duration}" >>"${LANE_FACTS}"

  # vector_results.jsonl record (controlled fields -> safe to build with python).
  python3 - "${VECTORS}" "${lane}" "${target}" "${category}" "${required}" \
    "${status}" "${passed}" "${failed}" "${ignored}" "${duration}" "${exit_code}" \
    "logs/${lane}.log" <<'PY'
import json, sys
out, lane, target, category, required, status, passed, failed, ignored, duration, exit_code, log = sys.argv[1:13]
rec = {
    "kind": "lane_result",
    "lane": lane, "target": target, "category": category,
    "required": required == "true", "status": status,
    "passed": int(passed), "failed": int(failed), "ignored": int(ignored),
    "duration_s": int(duration), "exit_code": int(exit_code), "log": log,
}
with open(out, "a") as f:
    f.write(json.dumps(rec, sort_keys=True) + "\n")
PY
  echo "[ytbg-gate]   -> status=${status} passed=${passed} failed=${failed} ignored=${ignored} (${duration}s)"
}

for entry in "${LANES[@]}"; do
  IFS='|' read -r lane target category required <<<"${entry}"
  run_lane "${lane}" "${target}" "${category}" "${required}"
done

OUTCOME="pass"
EXIT_CODE=0
if [ "${OVERALL_OK}" != "true" ]; then
  OUTCOME="fail"
  EXIT_CODE=3
fi

# run_manifest.json + summary.md (python assembles from the collected facts).
python3 - "${MANIFEST}" "${SUMMARY}" "${VECTORS}" "${COMMANDS}" "${LANE_FACTS}" \
  "${RUN_ID}" "${GIT_COMMIT}" "${GENERATED_AT}" "${TOOLCHAIN}" "${OUTCOME}" \
  "${POTOKEN_SUPPLIED}" "${YOUTUBE_SUPPLIED}" <<'PY'
import hashlib, json, sys

(manifest, summary, vectors, commands, facts, run_id, commit, generated_at,
 toolchain, outcome, potoken_supplied, youtube_supplied) = sys.argv[1:13]

lanes = []
with open(facts) as f:
    for line in f:
        line = line.rstrip("\n")
        if not line:
            continue
        lane, target, category, required, status, passed, failed, ignored, duration = line.split("\t")
        lanes.append({
            "lane": lane, "target": target, "category": category,
            "required": required == "true", "status": status,
            "passed": int(passed), "failed": int(failed), "ignored": int(ignored),
            "duration_s": int(duration),
        })

def sha256_file(path):
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(65536), b""):
            h.update(chunk)
    return "sha256:" + h.hexdigest()

required_lanes = [l for l in lanes if l["required"]]
required_failed = [l for l in required_lanes if l["status"] != "pass"]
total_passed = sum(l["passed"] for l in lanes)
total_failed = sum(l["failed"] for l in lanes)

manifest_obj = {
    "schema_version": "franken-engine.ytbg-release-gate.v1",
    "bead": "bd-8enww.5.7",
    "run_id": run_id,
    "generated_at": generated_at,
    "git_commit": commit,
    "toolchain": toolchain,
    "outcome": outcome,
    "summary": {
        "lane_count": len(lanes),
        "required_lane_count": len(required_lanes),
        "required_failed_count": len(required_failed),
        "total_vectors_passed": total_passed,
        "total_vectors_failed": total_failed,
    },
    "optional_fixtures": {
        "franken_whisper_po_token": {
            "env_var": "FRANKEN_ENGINE_POTOKEN_FIXTURES",
            "supplied": potoken_supplied == "true",
            "note": "absent optional fixtures pass via the structured-skip path and never fail the gate",
        },
        "real_youtube": {
            "env_var": "FRANKEN_ENGINE_YOUTUBE_FIXTURES",
            "supplied": youtube_supplied == "true",
            "note": "absent optional fixtures pass via the structured-skip path and never fail the gate",
        },
    },
    "lanes": lanes,
    "artifacts": {
        "commands": {"path": "commands.txt", "sha256": sha256_file(commands)},
        "vector_results": {"path": "vector_results.jsonl", "sha256": sha256_file(vectors)},
    },
}
with open(manifest, "w") as f:
    json.dump(manifest_obj, f, indent=2, sort_keys=True)
    f.write("\n")

lines = []
lines.append(f"# YTBG release gate — {run_id}")
lines.append("")
lines.append(f"- bead: `bd-8enww.5.7`")
lines.append(f"- commit: `{commit}`")
lines.append(f"- toolchain: `{toolchain}`")
lines.append(f"- generated: `{generated_at}`")
lines.append(f"- **outcome: {outcome.upper()}**")
lines.append("")
lines.append("| lane | category | required | status | passed | failed | ignored | dur(s) |")
lines.append("|---|---|---|---|---|---|---|---|")
for l in lanes:
    lines.append(
        f"| {l['lane']} | {l['category']} | {'yes' if l['required'] else 'no'} | "
        f"{l['status']} | {l['passed']} | {l['failed']} | {l['ignored']} | {l['duration_s']} |"
    )
lines.append("")
lines.append("## Optional franken_whisper fixtures")
lines.append("")
lines.append(f"- PO-token (`FRANKEN_ENGINE_POTOKEN_FIXTURES`): "
             f"{'SUPPLIED' if potoken_supplied == 'true' else 'absent (optional, structured-skip)'}")
lines.append(f"- Real YouTube (`FRANKEN_ENGINE_YOUTUBE_FIXTURES`): "
             f"{'SUPPLIED' if youtube_supplied == 'true' else 'absent (optional, structured-skip)'}")
lines.append("")
lines.append("An absent optional fixture is reported here and in `run_manifest.json`; it "
             "never fails the gate. A required-lane regression (a failed vector or a "
             "build/run error) exits the gate non-zero.")
if required_failed:
    lines.append("")
    lines.append("## Required-lane regressions")
    lines.append("")
    for l in required_failed:
        lines.append(f"- `{l['lane']}` ({l['target']}): status={l['status']}, "
                     f"failed={l['failed']} — see `logs/{l['lane']}.log`")
lines.append("")
with open(summary, "w") as f:
    f.write("\n".join(lines))

print(f"[ytbg-gate] outcome={outcome} "
      f"required_failed={len(required_failed)}/{len(required_lanes)} "
      f"vectors_passed={total_passed} vectors_failed={total_failed}")
PY

rm -f "${LANE_FACTS}"

echo "[ytbg-gate] manifest:  ${MANIFEST}"
echo "[ytbg-gate] summary:   ${SUMMARY}"
echo "[ytbg-gate] vectors:   ${VECTORS}"
echo "[ytbg-gate] commands:  ${COMMANDS}"
echo "[ytbg-gate] OUTCOME=${OUTCOME} (exit ${EXIT_CODE})"
exit "${EXIT_CODE}"
