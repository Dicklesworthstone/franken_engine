#!/usr/bin/env bash
#
# run_third_party_verifier.sh — N.4 operator / external-auditor surface for the
#                               third-party reproducibility verifier
#                               (Track N, bead bd-cixqu.14.4).
#
# This is the friendly, operator-facing wrapper around the *single source of
# truth* reproducibility checker `scripts/third_party_repro_lock_verifier.sh`
# (N.2, bd-cixqu.14.2). It re-checks a published claim-evidence bundle (the N.1
# triple `env.json` + `manifest.json` + `repro.lock` under
# `docs/evidence/<CLAIM>/`, bd-cixqu.14.1) and classifies the outcome so an
# operator — or an external auditor who has never seen the engine source —
# knows *what to do next*.
#
# Reconciliation note (honest scoping): N.2 shipped as a *scripted* verifier
# environment (`scripts/third_party_repro_lock_verifier.sh` +
# `docs/THIRD_PARTY_VERIFIER_TOOLKIT.md`), NOT a pre-built docker image — the
# only clean-room image in the repo is Track Y.2's proof-bundle verifier. So the
# default path here runs the scripted verifier directly on the host (`--via
# local`). An optional `--via docker` runs the *same* scripted verifier inside a
# caller-supplied pinned base image (`--image` / $THIRD_PARTY_VERIFIER_IMAGE) so
# auditors who want hermetic isolation can bring their own trusted clean room.
# The trust path never forks: both modes invoke the identical N.2 checker, so a
# verdict can never drift between them.
#
# The verifier re-checks a SINGLE dimension: does the locked deterministic replay
# plan validate (and, with --execute, re-run to the expected outcome)? This
# wrapper reports a SECOND, ORTHOGONAL dimension the checker does not: whether
# the *recorded* environment (`env.json`) drifts from the environment doing the
# replay, via `runbooks/scripts/diagnose_env_drift.sh` (N.4). Because the two
# dimensions are independent, the wrapper cleanly separates:
#
#   * verified              — the lock validated (plan-only) or replayed to its
#                             expected outcome (--execute), and the environment
#                             is aligned or its drift is not material. Safe.
#   * env_drift             — the lock still validates, but the recorded env.json
#                             differs from the replay host. Advisory: reproduce on
#                             a matching platform / toolchain before concluding.
#   * verification_failed   — the verifier rejected the lock or a replay command
#                             failed. The artifact is NOT verified. ESCALATE.
#   * bundle_incomplete     — the N.1 triple is missing a member. Re-export the
#                             bundle before verifying.
#
# Per bd-cixqu.45 logging discipline: every run writes a content-addressed bundle
# under artifacts/third_party_verifier_operator/<UTC-ts>/ with events.jsonl,
# commands.txt, the classified operator verdict, the raw N.2 verifier report, the
# env-drift verdict (when run), and a run_manifest.json carrying per-artifact
# sha256 + operator-verification commands.
#
# Modes:
#   verify <bundle-dir|repro.lock> [flags]   classify a target bundle/lock
#   selftest                                 fixture-driven proof of every class
#   -h | --help                              usage
#
# verify flags:
#   --via local|docker        checker execution path (default local)
#   --image <ref>             pinned clean-room image for --via docker
#   --execute                 actually re-run the locked replay (needs cargo/rch);
#                             default is --plan-only (validate + derive plan)
#   --no-diagnose             skip env-drift diagnosis even if env.json is present
#   --current-env <env.json>  diagnose drift against this snapshot (hermetic);
#                             default captures the live host
#   --strict-drift            promote env_drift from advisory (exit 0) to error (2)
#   --json-out <path>         also write the classified operator verdict JSON
#   --artifact-root <dir>     override the run-bundle root (default artifacts/)
#
# Exit codes:
#   0  verified (or env_drift in advisory mode)
#   1  verification_failed / bundle_incomplete (fail-closed; escalate)
#   2  env_drift under --strict-drift (reproduce on a matching environment)
#   3  CLI / environment error (target missing, docker requested but unavailable)
#
set -euo pipefail

export TZ=UTC
export LC_ALL=C
export LANG=C
export LANGUAGE=C

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
readonly SCRIPT_DIR
ROOT_DIR="$(cd "${SCRIPT_DIR}/../.." && pwd)"
readonly ROOT_DIR
cd "${ROOT_DIR}"

readonly COMPONENT="third_party_verifier_operator"
readonly BEAD_ID="bd-cixqu.14.4"
readonly OPERATOR_VERDICT_SCHEMA="franken-engine.third-party-verifier-operator-verdict.v1"
readonly EVENT_SCHEMA="franken-engine.evidence-record.v1"
# Single source of truth: the N.2 scripted verifier. The N.4 surface never
# re-implements the recheck protocol; it only orchestrates + classifies.
readonly N2_VERIFIER="scripts/third_party_repro_lock_verifier.sh"
readonly DRIFT_DIAGNOSER="runbooks/scripts/diagnose_env_drift.sh"
readonly ARTIFACT_ROOT_DEFAULT="${ROOT_DIR}/artifacts/${COMPONENT}"

usage() {
  cat >&2 <<EOF
usage: $0 verify <bundle-dir|repro.lock> [flags]
       $0 selftest
       $0 -h | --help

verify flags:
  --via local|docker       checker path (default local; docker = same N.2 checker
                           inside a caller-supplied pinned image via --image)
  --image <ref>            clean-room image for --via docker (or \$THIRD_PARTY_VERIFIER_IMAGE)
  --execute                re-run the locked replay (needs cargo/rch); default plan-only
  --no-diagnose            skip env-drift diagnosis even with env.json present
  --current-env <env.json> diagnose drift against this snapshot (default: live host)
  --strict-drift           treat env_drift as a hard error (exit 2)
  --json-out <path>        also write the classified operator verdict JSON
  --artifact-root <dir>    override run-bundle root

exit: 0 verified/advisory-drift · 1 verification_failed/bundle_incomplete · 2 strict drift · 3 CLI/env
EOF
}

die() {
  echo "[${COMPONENT}] ERROR: $*" >&2
  exit 3
}

iso_now() { date -u +%Y-%m-%dT%H:%M:%SZ; }

sha256_of() {
  if [[ -f "$1" ]]; then sha256sum "$1" | awk '{print $1}'; else printf ''; fi
}

# --- run-bundle plumbing (bd-cixqu.45) --------------------------------------
RUN_DIR=""
EVENTS_PATH=""
COMMANDS_PATH=""
TRACE_ID=""

init_run_bundle() {
  local artifact_root="$1" ts
  ts="$(date -u +%Y%m%dT%H%M%SZ)"
  RUN_DIR="${artifact_root}/${ts}"
  EVENTS_PATH="${RUN_DIR}/events.jsonl"
  COMMANDS_PATH="${RUN_DIR}/commands.txt"
  TRACE_ID="trace-${COMPONENT}-${ts}"
  mkdir -p "${RUN_DIR}"
  : >"${EVENTS_PATH}"
  : >"${COMMANDS_PATH}"
}

log_event() {
  # log_event <kind> <status> <detail-json>
  local kind="$1" status="$2" detail="$3" now
  now="$(iso_now)"
  jq -cn \
    --arg schema "${EVENT_SCHEMA}" \
    --arg ts "${now}" \
    --arg component "${COMPONENT}" \
    --arg trace_id "${TRACE_ID}" \
    --arg kind "${kind}" \
    --arg status "${status}" \
    --argjson detail "${detail:-{\}}" \
    '{schema_id:$schema, generated_utc:$ts, component:$component, trace_id:$trace_id, kind:$kind, status:$status, detail:$detail}' \
    >>"${EVENTS_PATH}"
}

record_cmd() { printf '$ %s\n' "$*" >>"${COMMANDS_PATH}"; }

# Run the N.2 scripted verifier on a lock via the host. Args: <lock> <plan_flag>
# <report_out>. Returns the verifier exit code (0 ok / 1 reject / 2 env).
run_n2_local() {
  local lock="$1" plan_flag="$2" report_out="$3"
  [[ -f "${N2_VERIFIER}" ]] || die "N.2 verifier not found: ${N2_VERIFIER}"
  local rc=0
  if [[ "${plan_flag}" == "plan-only" ]]; then
    record_cmd "bash ${N2_VERIFIER} --lock ${lock} --plan-only --report ${report_out}"
    bash "${N2_VERIFIER}" --lock "${lock}" --plan-only --report "${report_out}" \
      >>"${COMMANDS_PATH}" 2>&1 || rc=$?
  else
    record_cmd "bash ${N2_VERIFIER} --lock ${lock} --report ${report_out}"
    bash "${N2_VERIFIER}" --lock "${lock}" --report "${report_out}" \
      >>"${COMMANDS_PATH}" 2>&1 || rc=$?
  fi
  return "${rc}"
}

# Run the SAME N.2 verifier inside a caller-supplied pinned clean-room image.
# Args: <lock> <image> <report_out>. plan-only only (a clean room has no
# cargo/rch). Returns the container exit code.
run_n2_docker() {
  local lock="$1" image="$2" report_out="$3"
  command -v docker >/dev/null 2>&1 || die "docker not found on PATH (use --via local)"
  docker info >/dev/null 2>&1 || die "docker daemon not reachable (use --via local)"
  [[ -n "${image}" ]] || die "--via docker needs --image <ref> or \$THIRD_PARTY_VERIFIER_IMAGE (N.2 ships no pre-built image)"
  # The lock path is repo-relative; mount the repo read-only as the clean room.
  # The report is captured from the container's stdout (the mount is read-only).
  record_cmd "docker run --rm --network=none -v ${ROOT_DIR}:/work:ro -w /work ${image} bash ${N2_VERIFIER} --lock ${lock} --plan-only"
  local rc=0
  # Report is emitted to stdout (the read-only mount cannot be written); capture it.
  docker run --rm --network=none -v "${ROOT_DIR}:/work:ro" -w /work "${image}" \
    bash "${N2_VERIFIER}" --lock "${lock}" --plan-only >"${report_out}" 2>>"${COMMANDS_PATH}" || rc=$?
  return "${rc}"
}

# --- classification core ------------------------------------------------------
classify_and_emit() {
  # classify_and_emit <report_out> <verifier_rc> <via> <mode> <target> <lock>
  #   <triple_missing_json> <drift_verdict_or_empty> <classified_out>
  local report_out="$1" verifier_rc="$2" via="$3" mode="$4" target="$5" lock="$6"
  local triple_missing="$7" drift_verdict="$8" classified_out="$9"
  local now drift_json="null"
  now="$(iso_now)"
  if [[ -n "${drift_verdict}" && -f "${drift_verdict}" ]]; then
    drift_json="$(cat "${drift_verdict}")"
  fi
  TPV_REPORT="${report_out}" TPV_RC="${verifier_rc}" TPV_VIA="${via}" \
  TPV_MODE="${mode}" TPV_TARGET="${target}" TPV_LOCK="${lock}" \
  TPV_TRIPLE="${triple_missing}" TPV_SCHEMA="${OPERATOR_VERDICT_SCHEMA}" \
  TPV_BEAD="${BEAD_ID}" TPV_COMPONENT="${COMPONENT}" TPV_NOW="${now}" \
  TPV_DRIFT="${drift_json}" \
  python3 - "${classified_out}" <<'PY'
import json
import os
import sys

out_path = sys.argv[1]

try:
    with open(os.environ["TPV_REPORT"], encoding="utf-8") as fh:
        report = json.load(fh)
except Exception as exc:  # noqa: BLE001 — fail closed if the checker emitted nothing
    report = {"verdict": "fail", "command_count": 0,
              "lock_schema_version": "", "source_commit": "",
              "_parse_error": str(exc)}

verifier_rc = int(os.environ["TPV_RC"])
lock_verdict = report.get("verdict", "fail")
command_count = report.get("command_count", 0)
triple_missing = json.loads(os.environ["TPV_TRIPLE"])
drift = json.loads(os.environ["TPV_DRIFT"])
mode = os.environ["TPV_MODE"]

# Pass shapes: plan-only => "planned" (rc 0); --execute => "pass" (rc 0).
verifier_ok = verifier_rc == 0 and lock_verdict in ("planned", "pass")

env_drift_detected = bool(drift) and drift.get("drift_detected", False)

if triple_missing:
    classification = "bundle_incomplete"
    next_action = ("Re-export the claim-evidence bundle: the N.1 triple is "
                   "missing %s. A bundle must carry env.json + manifest.json + "
                   "repro.lock." % ", ".join(triple_missing))
elif not verifier_ok:
    classification = "verification_failed"
    next_action = ("The third-party verifier rejected this lock (verdict=%s, "
                   "rc=%d). The artifact is NOT verified — escalate to the "
                   "FrankenEngine maintainers." % (lock_verdict, verifier_rc))
elif env_drift_detected:
    classification = "env_drift"
    classes = drift.get("drift_class_count", {})
    next_action = ("The lock validates, but the recorded environment drifts "
                   "from the replay host (platform=%d, toolchain=%d, "
                   "dependency=%d). Reproduce on a matching environment before "
                   "concluding, or accept advisory if the drift is immaterial." % (
                       classes.get("platform", 0),
                       classes.get("toolchain", 0),
                       classes.get("dependency", 0)))
else:
    classification = "verified"
    if mode == "plan-only":
        next_action = ("The deterministic replay plan validated (%d command(s)) "
                       "and the environment is aligned. Re-run with --execute on "
                       "a matching host to replay end-to-end." % command_count)
    else:
        next_action = ("The locked replay re-ran to its expected outcome and the "
                       "environment is aligned. Safe to rely on.")

# Exit code mapping is decided by the shell; we surface the intended one.
if classification in ("bundle_incomplete", "verification_failed"):
    exit_code = 1
elif classification == "env_drift":
    exit_code = 0  # advisory; --strict-drift promotes to 2 in the shell
else:
    exit_code = 0

doc = {
    "schema_version": os.environ["TPV_SCHEMA"],
    "component": os.environ["TPV_COMPONENT"],
    "bead_id": os.environ["TPV_BEAD"],
    "generated_at_utc": os.environ["TPV_NOW"],
    "target": os.environ["TPV_TARGET"],
    "lock": os.environ["TPV_LOCK"],
    "via": os.environ["TPV_VIA"],
    "mode": mode,
    "bundle_complete": len(triple_missing) == 0,
    "triple_missing": triple_missing,
    "verifier_verdict": lock_verdict,
    "verifier_rc": verifier_rc,
    "lock_schema_version": report.get("lock_schema_version", ""),
    "source_commit": report.get("source_commit", ""),
    "command_count": command_count,
    "env_drift": {
        "diagnosed": bool(drift),
        "verdict": (drift.get("verdict") if drift else "skipped"),
        "drift_class_count": (drift.get("drift_class_count") if drift else None),
    },
    "classification": classification,
    "intended_exit_code": exit_code,
    "next_action": next_action,
}

payload = json.dumps(doc, indent=2, sort_keys=True)
with open(out_path, "w", encoding="utf-8") as fh:
    fh.write(payload + "\n")
sys.stdout.write(payload + "\n")
PY
}

write_manifest() {
  local outcome="$1" verdict_path="$2" report_path="$3" drift_path="$4"
  local manifest_path="${RUN_DIR}/run_manifest.json"
  local git_commit
  git_commit="$( (cd "${ROOT_DIR}" && git rev-parse HEAD 2>/dev/null) || echo unknown )"
  jq -n \
    --arg schema "franken-engine.third-party-verifier-operator.run-manifest.v1" \
    --arg component "${COMPONENT}" \
    --arg bead "${BEAD_ID}" \
    --arg ts "$(iso_now)" \
    --arg git_commit "${git_commit}" \
    --arg outcome "${outcome}" \
    --arg trace_id "${TRACE_ID}" \
    --arg events_sha "$(sha256_of "${EVENTS_PATH}")" \
    --arg verdict_sha "$(sha256_of "${verdict_path}")" \
    --arg report_sha "$(sha256_of "${report_path}")" \
    --arg drift_sha "$(sha256_of "${drift_path}")" \
    --arg commands_sha "$(sha256_of "${COMMANDS_PATH}")" \
    --arg replay "runbooks/scripts/run_third_party_verifier.sh selftest" \
    '{
      schema_version: $schema,
      component: $component,
      bead_id: $bead,
      generated_at_utc: $ts,
      git_commit: $git_commit,
      outcome: $outcome,
      trace_id: $trace_id,
      artifacts: {
        "events.jsonl": $events_sha,
        "operator_verdict.json": $verdict_sha,
        "n2_verifier_report.json": $report_sha,
        "env_drift_verdict.json": $drift_sha,
        "commands.txt": $commands_sha
      },
      operator_replay_command: $replay
    }' >"${manifest_path}"
}

cmd_verify() {
  local target="" via="local" image="${THIRD_PARTY_VERIFIER_IMAGE:-}" mode="plan-only"
  local diagnose=1 current_env="" strict_drift=0 json_out="" artifact_root="${ARTIFACT_ROOT_DEFAULT}"
  target="${1:-}"
  [[ -n "${target}" && "${target}" != --* ]] || { usage; die "verify needs a <bundle-dir|repro.lock> target"; }
  shift || true
  while [[ $# -gt 0 ]]; do
    case "$1" in
      --via) via="${2:-}"; shift 2 ;;
      --image) image="${2:-}"; shift 2 ;;
      --execute) mode="execute"; shift ;;
      --no-diagnose) diagnose=0; shift ;;
      --current-env) current_env="${2:-}"; shift 2 ;;
      --strict-drift) strict_drift=1; shift ;;
      --json-out) json_out="${2:-}"; shift 2 ;;
      --artifact-root) artifact_root="${2:-}"; shift 2 ;;
      -h|--help) usage; exit 0 ;;
      *) usage; die "unknown argument: $1" ;;
    esac
  done

  command -v jq >/dev/null 2>&1 || die "jq is required"
  command -v python3 >/dev/null 2>&1 || die "python3 is required"
  case "${via}" in local|docker) ;; *) die "--via must be local|docker (got ${via})" ;; esac
  [[ -e "${target}" ]] || die "target not found: ${target}"

  # Resolve the lock + the bundle dir (if any), and the N.1 triple.
  local lock bundle_dir env_json
  local -a triple_missing=()
  if [[ -d "${target}" ]]; then
    bundle_dir="${target%/}"
    lock="${bundle_dir}/repro.lock"
    env_json="${bundle_dir}/env.json"
    for f in env.json manifest.json repro.lock; do
      [[ -f "${bundle_dir}/${f}" ]] || triple_missing+=("$f")
    done
  else
    lock="${target}"
    bundle_dir="$(dirname "${target}")"
    env_json="${bundle_dir}/env.json"
    # A bare-lock target is not held to triple completeness.
  fi

  init_run_bundle "${artifact_root}"
  log_event "begin" "info" "$(jq -cn --arg target "${target}" --arg via "${via}" --arg mode "${mode}" \
    '{target:$target, via:$via, mode:$mode}')"

  local report_path="${RUN_DIR}/n2_verifier_report.json"
  local verifier_rc=0

  if [[ -f "${lock}" ]]; then
    if [[ "${via}" == "docker" ]]; then
      run_n2_docker "${lock}" "${image}" "${report_path}" || verifier_rc=$?
    else
      run_n2_local "${lock}" "${mode}" "${report_path}" || verifier_rc=$?
    fi
    log_event "verify_lock" "info" "$(jq -cn --argjson rc "${verifier_rc}" --arg lock "${lock}" '{verifier_rc:$rc, lock:$lock}')"
  else
    # No lock at all → a maximally-incomplete bundle.
    verifier_rc=2
    [[ " ${triple_missing[*]:-} " == *" repro.lock "* ]] || triple_missing+=("repro.lock")
    printf '{"verdict":"fail","command_count":0,"lock_schema_version":"","source_commit":""}\n' >"${report_path}"
    log_event "verify_lock" "fail" "$(jq -cn --arg lock "${lock}" '{reason:"repro.lock absent", lock:$lock}')"
  fi

  # Orthogonal env-drift diagnosis (advisory).
  local drift_verdict=""
  if [[ "${diagnose}" -eq 1 && -f "${env_json}" ]]; then
    drift_verdict="${RUN_DIR}/env_drift_verdict.json"
    local -a drift_args=(diagnose --recorded "${env_json}" --json-out "${drift_verdict}"
                         --artifact-root "${RUN_DIR}/drift" --quiet)
    [[ -f "${lock}" ]] && drift_args+=(--lock "${lock}")
    [[ -n "${current_env}" ]] && drift_args+=(--current "${current_env}")
    record_cmd "bash ${DRIFT_DIAGNOSER} ${drift_args[*]}"
    bash "${DRIFT_DIAGNOSER}" "${drift_args[@]}" >/dev/null 2>&1 || true
    log_event "diagnose_drift" "info" "$(jq -cn --argjson v "$(cat "${drift_verdict}")" '{verdict:$v.verdict, drift_class_count:$v.drift_class_count}')"
  fi

  local triple_json
  triple_json="$(printf '%s\n' "${triple_missing[@]:-}" | jq -R . | jq -s 'map(select(length>0))')"

  local verdict_path="${RUN_DIR}/operator_verdict.json"
  classify_and_emit "${report_path}" "${verifier_rc}" "${via}" "${mode}" "${target}" "${lock}" \
    "${triple_json}" "${drift_verdict}" "${verdict_path}" >"${RUN_DIR}/operator_verdict.stdout"

  local classification exit_code
  classification="$(jq -r '.classification' "${verdict_path}")"
  case "${classification}" in
    verified) exit_code=0 ;;
    env_drift) if [[ "${strict_drift}" -eq 1 ]]; then exit_code=2; else exit_code=0; fi ;;
    verification_failed|bundle_incomplete) exit_code=1 ;;
    *) exit_code=1 ;;
  esac

  write_manifest "${classification}" "${verdict_path}" "${report_path}" "${drift_verdict:-}"
  log_event "finish" "info" "$(jq -cn --arg c "${classification}" --argjson ec "${exit_code}" --arg run_dir "${RUN_DIR}" \
    '{classification:$c, exit_code:$ec, run_dir:$run_dir}')"

  if [[ -n "${json_out}" ]]; then
    mkdir -p "$(dirname "${json_out}")"
    cp "${verdict_path}" "${json_out}"
  fi

  cat "${verdict_path}"
  echo "[${COMPONENT}] classification=${classification} exit=${exit_code} run_dir=${RUN_DIR}" >&2
  exit "${exit_code}"
}

# Fixture-driven self-proof: builds valid/drifted/tampered bundles in a temp dir
# and asserts the wrapper classifies each correctly. No engine build.
cmd_selftest() {
  command -v jq >/dev/null 2>&1 || die "jq is required"
  command -v python3 >/dev/null 2>&1 || die "python3 is required"
  [[ -f "${N2_VERIFIER}" ]] || die "N.2 verifier missing: ${N2_VERIFIER}"
  local tmp failures=0
  tmp="$(mktemp -d "${TMPDIR:-/tmp}/tpv_selftest.XXXXXX")"

  mk_lock() {
    cat >"$1" <<'JSON'
{
  "schema_version": "frankenengine.reproducibility.lock.v1",
  "source_commit": "0000000000000000000000000000000000000000",
  "determinism": {"mode": "strict", "reproducible_builds": true, "seed_control": "fixed"},
  "replay": {"command_sequence": ["echo deterministic-replay-ok"]},
  "inputs": {"dependencies": ["Cargo.toml"]}
}
JSON
  }
  mk_env() {
    cat >"$1" <<'JSON'
{
  "host": {"architecture": "x86_64", "kernel": "6.17.0-22-generic", "os_version": "Ubuntu 22.04 LTS", "platform": "linux"},
  "toolchain": {"cargo_version": "1.81.0", "rust_version": "1.81.0-nightly", "rustc_target": "x86_64-unknown-linux-gnu"},
  "project": {"commit": "0000000000000000000000000000000000000000"},
  "schema_version": "frankenengine.reproducibility.env.v1"
}
JSON
  }

  expect_class() {
    local label="$1" want="$2" got
    got="$(jq -r '.classification' "$3" 2>/dev/null || echo "<none>")"
    if [[ "${got}" != "${want}" ]]; then
      echo "selftest: ${label}: expected ${want}, got ${got}" >&2
      failures=$((failures+1))
    fi
  }

  # 1. complete + aligned bundle → verified
  local b1="${tmp}/b1"; mkdir -p "${b1}"
  mk_lock "${b1}/repro.lock"; mk_env "${b1}/env.json"; echo '{}' >"${b1}/manifest.json"
  "${BASH_SOURCE[0]}" verify "${b1}" --current-env "${b1}/env.json" \
    --json-out "${tmp}/v1.json" --artifact-root "${tmp}/art" >/dev/null 2>&1 || true
  expect_class "aligned bundle" "verified" "${tmp}/v1.json"

  # 2. drifted env → env_drift (advisory exit 0)
  local b2="${tmp}/b2"; mkdir -p "${b2}"
  mk_lock "${b2}/repro.lock"; mk_env "${b2}/env.json"; echo '{}' >"${b2}/manifest.json"
  jq '.toolchain.cargo_version="1.99.0"' "${b2}/env.json" >"${tmp}/drift_env.json"
  local rc2=0
  "${BASH_SOURCE[0]}" verify "${b2}" --current-env "${tmp}/drift_env.json" \
    --json-out "${tmp}/v2.json" --artifact-root "${tmp}/art" >/dev/null 2>&1 || rc2=$?
  expect_class "drifted env" "env_drift" "${tmp}/v2.json"
  [[ "${rc2}" -eq 0 ]] || { echo "selftest: env_drift should be advisory exit 0 (got ${rc2})" >&2; failures=$((failures+1)); }

  # 3. tampered lock (invalid JSON) → verification_failed (exit 1)
  local b3="${tmp}/b3"; mkdir -p "${b3}"
  echo 'this is not json' >"${b3}/repro.lock"; mk_env "${b3}/env.json"; echo '{}' >"${b3}/manifest.json"
  "${BASH_SOURCE[0]}" verify "${b3}" --current-env "${b3}/env.json" \
    --json-out "${tmp}/v3.json" --artifact-root "${tmp}/art" >/dev/null 2>&1 || true
  expect_class "tampered lock" "verification_failed" "${tmp}/v3.json"

  # 4. incomplete triple (no manifest.json) → bundle_incomplete (exit 1)
  local b4="${tmp}/b4"; mkdir -p "${b4}"
  mk_lock "${b4}/repro.lock"; mk_env "${b4}/env.json"
  "${BASH_SOURCE[0]}" verify "${b4}" --current-env "${b4}/env.json" \
    --json-out "${tmp}/v4.json" --artifact-root "${tmp}/art" >/dev/null 2>&1 || true
  expect_class "incomplete triple" "bundle_incomplete" "${tmp}/v4.json"

  # 5. drifted env under --strict-drift → exit 2
  local rc5=0
  "${BASH_SOURCE[0]}" verify "${b2}" --current-env "${tmp}/drift_env.json" --strict-drift \
    --artifact-root "${tmp}/art" >/dev/null 2>&1 || rc5=$?
  [[ "${rc5}" -eq 2 ]] || { echo "selftest: --strict-drift should exit 2 (got ${rc5})" >&2; failures=$((failures+1)); }

  rm -rf "${tmp}"
  if [[ "${failures}" -eq 0 ]]; then
    echo "[${COMPONENT}] selftest: PASS (5 classification fixtures)"
    return 0
  fi
  echo "[${COMPONENT}] selftest: FAIL (${failures} mismatches)" >&2
  return 1
}

main() {
  local mode="${1:-}"
  case "${mode}" in
    verify) shift; cmd_verify "$@" ;;
    selftest) shift; cmd_selftest "$@" ;;
    -h|--help|"") usage; [[ -n "${mode}" ]] && exit 0 || exit 3 ;;
    *) usage; die "unknown mode: ${mode}" ;;
  esac
}

main "$@"
