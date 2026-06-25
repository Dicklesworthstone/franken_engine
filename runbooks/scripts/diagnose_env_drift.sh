#!/usr/bin/env bash
#
# diagnose_env_drift.sh — N.4 reproducibility environment-drift diagnostician
#                         (Track N, bead bd-cixqu.14.4).
#
# When the third-party reproducibility verifier
# (`scripts/third_party_repro_lock_verifier.sh`, N.2) replays a published
# `repro.lock` and the result diverges, the first operator question is *why*:
# is the divergence because the machine doing the replay differs from the
# machine that recorded the artifact, or because the artifact itself regressed?
# This script answers the first half — it diffs a *recorded* `env.json`
# (emitted alongside every claim's `repro.lock` by N.1) against the *current*
# replaying environment and classifies every difference into exactly one of
# three operator-actionable buckets:
#
#   * platform drift    — host.architecture / host.kernel / host.os_version /
#                         host.platform changed. The replay ran on a different
#                         machine class. Reproduce on a matching platform (or
#                         accept that platform-sensitive outputs may differ).
#   * toolchain drift   — toolchain.cargo_version / rust_version / rustc_target
#                         changed. Pin the recorded toolchain before drawing a
#                         conclusion about the artifact.
#   * dependency drift  — project.commit moved, or (with --lock) the locked
#                         primary artifact's sha256 / a declared dependency file
#                         changed. The *inputs* differ, so a divergent replay is
#                         expected, not a regression.
#
# Only once all three buckets are empty (env aligned) does a divergent verify
# implicate the artifact/claim itself.
#
# The "current" environment is captured live from the host by default; pass
# `--current <env.json>` to compare two recorded snapshots (used by the unit
# tests and by auditors comparing two published releases). This mirrors the
# Y.4 wrapper's `--installed-*`/`--expected-*` override discipline: the live
# capture is convenient, the explicit override is hermetic.
#
# Per bd-cixqu.45 logging discipline: every run writes a content-addressed
# bundle under artifacts/env_drift_diagnosis/<UTC-ts>/ with events.jsonl,
# commands.txt, the typed verdict JSON, and a run_manifest.json carrying
# per-artifact sha256 + the operator replay command.
#
# Modes:
#   diagnose --recorded <env.json> [flags]   classify recorded-vs-current drift
#   selftest                                 fixture-driven proof of every class
#   -h | --help                              usage
#
# diagnose flags:
#   --recorded <env.json>    REQUIRED. The recorded environment snapshot.
#   --current  <env.json>    Compare against this snapshot instead of the host.
#   --lock     <repro.lock>  Also diff locked input hashes (dependency drift).
#   --json-out <path>        Also write the typed verdict JSON here.
#   --artifact-root <dir>    Override the run-bundle root (default artifacts/).
#   --quiet                  Suppress the human summary on stdout.
#
# Exit codes:
#   0  aligned (no drift detected)
#   1  drift detected (see the typed verdict for the per-class breakdown)
#   2  CLI / environment error (missing or malformed input)
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

readonly COMPONENT="env_drift_diagnosis"
readonly BEAD_ID="bd-cixqu.14.4"
readonly VERDICT_SCHEMA="franken-engine.env-drift-diagnosis.v1"
readonly EVENT_SCHEMA="franken-engine.evidence-record.v1"
readonly ARTIFACT_ROOT_DEFAULT="${ROOT_DIR}/artifacts/${COMPONENT}"

usage() {
  cat >&2 <<EOF
usage: $0 diagnose --recorded <env.json> [flags]
       $0 selftest
       $0 -h | --help

diagnose flags:
  --recorded <env.json>   REQUIRED. recorded environment snapshot
  --current  <env.json>   compare against this snapshot instead of the live host
  --lock     <repro.lock> also diff locked input hashes (dependency drift)
  --json-out <path>       also write the typed verdict JSON here
  --artifact-root <dir>   override run-bundle root (default artifacts/${COMPONENT})
  --quiet                 suppress the human summary on stdout

exit: 0 aligned · 1 drift detected · 2 CLI/env error
EOF
}

die() {
  echo "[${COMPONENT}] ERROR: $*" >&2
  exit 2
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

# Capture the live host environment into an env.json-shaped snapshot on stdout.
capture_current_env() {
  local arch kernel platform os_ver cargo_v rust_v rustc_target commit
  arch="$(uname -m 2>/dev/null || echo unknown)"
  kernel="$(uname -r 2>/dev/null || echo unknown)"
  platform="$(uname -s 2>/dev/null | tr '[:upper:]' '[:lower:]' || echo unknown)"
  if [[ -r /etc/os-release ]]; then
    # shellcheck disable=SC1091
    os_ver="$( . /etc/os-release 2>/dev/null; printf '%s' "${PRETTY_NAME:-${NAME:-unknown}}" )"
  else
    os_ver="$(uname -sr 2>/dev/null || echo unknown)"
  fi
  cargo_v="$(cargo --version 2>/dev/null | grep -oE '[0-9]+\.[0-9]+\.[0-9]+[^ ]*' | head -n1 || true)"
  rust_v="$(rustc --version 2>/dev/null | grep -oE '[0-9]+\.[0-9]+\.[0-9]+[^ ]*' | head -n1 || true)"
  rustc_target="$(rustc -vV 2>/dev/null | awk -F': ' '/^host:/{print $2}' | head -n1 || true)"
  commit="$( (cd "${ROOT_DIR}" && git rev-parse HEAD 2>/dev/null) || echo unknown )"
  jq -n \
    --arg arch "${arch}" --arg kernel "${kernel}" \
    --arg platform "${platform}" --arg os_ver "${os_ver}" \
    --arg cargo_v "${cargo_v}" --arg rust_v "${rust_v}" \
    --arg rustc_target "${rustc_target}" --arg commit "${commit}" \
    '{
      captured_at_utc: "live-host",
      host: {architecture:$arch, kernel:$kernel, os_version:$os_ver, platform:$platform},
      toolchain: {cargo_version:$cargo_v, rust_version:$rust_v, rustc_target:$rustc_target},
      project: {commit:$commit},
      schema_version: "frankenengine.reproducibility.env.v1"
    }'
}

# The diff engine. Args: <recorded.json> <current.json> <lock-or-empty>
#   <repo-root> <current-source-label> <verdict-out>. Writes the typed verdict
# to <verdict-out> and stdout, returns 0 aligned / 1 drift.
diff_and_emit() {
  local recorded="$1" current="$2" lock="$3" root="$4" cur_label="$5" verdict_out="$6"
  local now
  now="$(iso_now)"
  ED_RECORDED="${recorded}" ED_CURRENT="${current}" ED_LOCK="${lock}" \
  ED_ROOT="${root}" ED_CURLABEL="${cur_label}" ED_SCHEMA="${VERDICT_SCHEMA}" \
  ED_COMPONENT="${COMPONENT}" ED_BEAD="${BEAD_ID}" ED_NOW="${now}" \
  python3 - "${verdict_out}" <<'PY'
import hashlib
import json
import os
import sys

out_path = sys.argv[1]


def load(path):
    with open(path, encoding="utf-8") as fh:
        return json.load(fh)


def get(d, dotted):
    cur = d
    for key in dotted.split("."):
        if isinstance(cur, dict) and key in cur:
            cur = cur[key]
        else:
            return None
    return cur


def sha256_file(path):
    try:
        h = hashlib.sha256()
        with open(path, "rb") as fh:
            for chunk in iter(lambda: fh.read(65536), b""):
                h.update(chunk)
        return h.hexdigest()
    except OSError:
        return None


recorded = load(os.environ["ED_RECORDED"])
current = load(os.environ["ED_CURRENT"])
root = os.environ["ED_ROOT"]

# (class, dotted-field) pairs compared between recorded and current env.json.
FIELDS = [
    ("platform", "host.architecture"),
    ("platform", "host.kernel"),
    ("platform", "host.os_version"),
    ("platform", "host.platform"),
    ("toolchain", "toolchain.cargo_version"),
    ("toolchain", "toolchain.rust_version"),
    ("toolchain", "toolchain.rustc_target"),
    ("dependency", "project.commit"),
]

drifts = []
for cls, field in FIELDS:
    rv = get(recorded, field)
    cv = get(current, field)
    if rv is None and cv is None:
        # field absent on both sides — nothing recorded to compare, skip.
        continue
    if rv != cv:
        drifts.append({"class": cls, "field": field, "recorded": rv, "current": cv})

# Lock-derived dependency drift: the recorded primary artifact hash and the
# existence of every declared dependency file, checked against the live tree.
lock_path = os.environ.get("ED_LOCK", "")
lock_checked = False
if lock_path:
    try:
        lock = load(lock_path)
        lock_checked = True
    except (OSError, json.JSONDecodeError):
        lock = None
        lock_checked = False
    if lock is not None:
        primary = (lock.get("inputs") or {}).get("primary_artifact") or {}
        rec_hash = primary.get("hash")
        rel = primary.get("path")
        if rec_hash and rel:
            abspath = rel if os.path.isabs(rel) else os.path.join(root, rel)
            cur_hash = sha256_file(abspath)
            if cur_hash != rec_hash:
                drifts.append({
                    "class": "dependency",
                    "field": "inputs.primary_artifact.hash",
                    "recorded": rec_hash,
                    "current": cur_hash if cur_hash is not None else "<missing-file>",
                })
        for dep in (lock.get("inputs") or {}).get("dependencies", []) or []:
            if not isinstance(dep, str):
                continue
            abspath = dep if os.path.isabs(dep) else os.path.join(root, dep)
            if not os.path.exists(abspath):
                drifts.append({
                    "class": "dependency",
                    "field": "inputs.dependencies",
                    "recorded": dep,
                    "current": "<missing-file>",
                })

classes = {"platform": 0, "toolchain": 0, "dependency": 0}
for d in drifts:
    classes[d["class"]] += 1

drift_detected = len(drifts) > 0
verdict = "drift" if drift_detected else "aligned"

doc = {
    "schema_version": os.environ["ED_SCHEMA"],
    "component": os.environ["ED_COMPONENT"],
    "bead_id": os.environ["ED_BEAD"],
    "generated_at_utc": os.environ["ED_NOW"],
    "recorded_env": os.environ["ED_RECORDED"],
    "current_source": os.environ["ED_CURLABEL"],
    "lock_checked": lock_checked,
    "drift_detected": drift_detected,
    "drift_class_count": classes,
    "drifts": drifts,
    "verdict": verdict,
}

payload = json.dumps(doc, indent=2, sort_keys=True)
with open(out_path, "w", encoding="utf-8") as fh:
    fh.write(payload + "\n")
sys.stdout.write(payload + "\n")
sys.exit(1 if drift_detected else 0)
PY
}

write_manifest() {
  local outcome="$1" verdict_path="$2"
  local manifest_path="${RUN_DIR}/run_manifest.json"
  local git_commit
  git_commit="$( (cd "${ROOT_DIR}" && git rev-parse HEAD 2>/dev/null) || echo unknown )"
  jq -n \
    --arg schema "franken-engine.env-drift-diagnosis.run-manifest.v1" \
    --arg component "${COMPONENT}" \
    --arg bead "${BEAD_ID}" \
    --arg ts "$(iso_now)" \
    --arg git_commit "${git_commit}" \
    --arg outcome "${outcome}" \
    --arg trace_id "${TRACE_ID}" \
    --arg events_sha "$(sha256_of "${EVENTS_PATH}")" \
    --arg verdict_sha "$(sha256_of "${verdict_path}")" \
    --arg commands_sha "$(sha256_of "${COMMANDS_PATH}")" \
    --arg replay "runbooks/scripts/diagnose_env_drift.sh selftest" \
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
        "verdict.json": $verdict_sha,
        "commands.txt": $commands_sha
      },
      operator_replay_command: $replay
    }' >"${manifest_path}"
}

cmd_diagnose() {
  local recorded="" current="" lock="" json_out="" artifact_root="${ARTIFACT_ROOT_DEFAULT}" quiet=0
  while [[ $# -gt 0 ]]; do
    case "$1" in
      --recorded) recorded="${2:-}"; shift 2 ;;
      --current) current="${2:-}"; shift 2 ;;
      --lock) lock="${2:-}"; shift 2 ;;
      --json-out) json_out="${2:-}"; shift 2 ;;
      --artifact-root) artifact_root="${2:-}"; shift 2 ;;
      --quiet) quiet=1; shift ;;
      -h|--help) usage; exit 0 ;;
      *) usage; die "unknown argument: $1" ;;
    esac
  done

  command -v jq >/dev/null 2>&1 || die "jq is required"
  command -v python3 >/dev/null 2>&1 || die "python3 is required"
  [[ -n "${recorded}" ]] || { usage; die "--recorded is required"; }
  [[ -f "${recorded}" ]] || die "recorded env.json not found: ${recorded}"
  jq empty "${recorded}" >/dev/null 2>&1 || die "recorded env.json is not valid JSON: ${recorded}"
  if [[ -n "${lock}" ]]; then
    [[ -f "${lock}" ]] || die "repro.lock not found: ${lock}"
    jq empty "${lock}" >/dev/null 2>&1 || die "repro.lock is not valid JSON: ${lock}"
  fi

  init_run_bundle "${artifact_root}"
  log_event "begin" "info" "$(jq -cn --arg recorded "${recorded}" --arg lock "${lock}" '{recorded:$recorded, lock:$lock}')"

  # Resolve the "current" environment: explicit snapshot, or live host capture.
  local current_path cur_label
  if [[ -n "${current}" ]]; then
    [[ -f "${current}" ]] || die "current env.json not found: ${current}"
    jq empty "${current}" >/dev/null 2>&1 || die "current env.json is not valid JSON: ${current}"
    current_path="${current}"
    cur_label="${current}"
  else
    current_path="${RUN_DIR}/current_env.json"
    record_cmd "capture_current_env > ${current_path}"
    capture_current_env >"${current_path}"
    cur_label="live-host"
  fi

  local verdict_path="${RUN_DIR}/verdict.json"
  record_cmd "diagnose_env_drift diff ${recorded} vs ${cur_label}"
  local rc=0
  diff_and_emit "${recorded}" "${current_path}" "${lock}" "${ROOT_DIR}" "${cur_label}" "${verdict_path}" \
    >"${RUN_DIR}/verdict.stdout" || rc=$?

  local outcome
  if [[ "${rc}" -eq 0 ]]; then outcome="aligned"; else outcome="drift"; fi
  log_event "diagnose" "${outcome}" "$(jq -cn --argjson v "$(cat "${verdict_path}")" '{drift_class_count:$v.drift_class_count, verdict:$v.verdict}')"

  if [[ -n "${json_out}" ]]; then
    mkdir -p "$(dirname "${json_out}")"
    cp "${verdict_path}" "${json_out}"
  fi

  write_manifest "${outcome}" "${verdict_path}"
  log_event "finish" "info" "$(jq -cn --arg outcome "${outcome}" --arg run_dir "${RUN_DIR}" '{outcome:$outcome, run_dir:$run_dir}')"

  if [[ "${quiet}" -eq 0 ]]; then
    cat "${verdict_path}"
    echo "[${COMPONENT}] verdict=${outcome} run_dir=${RUN_DIR}" >&2
  fi
  return "${rc}"
}

# Fixture-driven self-proof of every drift class. No engine build; pure shell +
# jq + python3. Exits 0 only if every classification matches expectations.
cmd_selftest() {
  command -v jq >/dev/null 2>&1 || die "jq is required"
  command -v python3 >/dev/null 2>&1 || die "python3 is required"
  local tmp failures=0
  tmp="$(mktemp -d "${TMPDIR:-/tmp}/env_drift_selftest.XXXXXX")"

  cat >"${tmp}/recorded.json" <<'JSON'
{
  "host": {"architecture": "x86_64", "kernel": "6.17.0-22-generic", "os_version": "Ubuntu 22.04 LTS", "platform": "linux"},
  "toolchain": {"cargo_version": "1.81.0", "rust_version": "1.81.0-nightly", "rustc_target": "x86_64-unknown-linux-gnu"},
  "project": {"commit": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"},
  "schema_version": "frankenengine.reproducibility.env.v1"
}
JSON

  # 1. identical → aligned (exit 0)
  cp "${tmp}/recorded.json" "${tmp}/same.json"
  if "${BASH_SOURCE[0]}" diagnose --recorded "${tmp}/recorded.json" --current "${tmp}/same.json" \
       --json-out "${tmp}/v_same.json" --artifact-root "${tmp}/art" --quiet >/dev/null 2>&1; then
    [[ "$(jq -r '.verdict' "${tmp}/v_same.json")" == "aligned" ]] || { echo "selftest: identical should be aligned" >&2; failures=$((failures+1)); }
  else
    echo "selftest: identical env should exit 0" >&2; failures=$((failures+1))
  fi

  # 2. platform drift (kernel)
  jq '.host.kernel = "6.17.0-35-generic"' "${tmp}/recorded.json" >"${tmp}/plat.json"
  "${BASH_SOURCE[0]}" diagnose --recorded "${tmp}/recorded.json" --current "${tmp}/plat.json" \
     --json-out "${tmp}/v_plat.json" --artifact-root "${tmp}/art" --quiet >/dev/null 2>&1 || true
  if [[ "$(jq -r '.drift_class_count.platform' "${tmp}/v_plat.json")" != "1" ]]; then
    echo "selftest: kernel change should be 1 platform drift" >&2; failures=$((failures+1))
  fi

  # 3. toolchain drift (cargo)
  jq '.toolchain.cargo_version = "1.83.0"' "${tmp}/recorded.json" >"${tmp}/tool.json"
  "${BASH_SOURCE[0]}" diagnose --recorded "${tmp}/recorded.json" --current "${tmp}/tool.json" \
     --json-out "${tmp}/v_tool.json" --artifact-root "${tmp}/art" --quiet >/dev/null 2>&1 || true
  if [[ "$(jq -r '.drift_class_count.toolchain' "${tmp}/v_tool.json")" != "1" ]]; then
    echo "selftest: cargo change should be 1 toolchain drift" >&2; failures=$((failures+1))
  fi

  # 4. dependency drift (commit)
  jq '.project.commit = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"' "${tmp}/recorded.json" >"${tmp}/dep.json"
  "${BASH_SOURCE[0]}" diagnose --recorded "${tmp}/recorded.json" --current "${tmp}/dep.json" \
     --json-out "${tmp}/v_dep.json" --artifact-root "${tmp}/art" --quiet >/dev/null 2>&1 || true
  if [[ "$(jq -r '.drift_class_count.dependency' "${tmp}/v_dep.json")" != "1" ]]; then
    echo "selftest: commit change should be 1 dependency drift" >&2; failures=$((failures+1))
  fi

  # 5. combined all three classes drift
  jq '.host.platform = "darwin" | .toolchain.rust_version = "1.99.0" | .project.commit = "cccccccccccccccccccccccccccccccccccccccc"' \
     "${tmp}/recorded.json" >"${tmp}/all.json"
  "${BASH_SOURCE[0]}" diagnose --recorded "${tmp}/recorded.json" --current "${tmp}/all.json" \
     --json-out "${tmp}/v_all.json" --artifact-root "${tmp}/art" --quiet >/dev/null 2>&1 || true
  if [[ "$(jq -r '[.drift_class_count.platform, .drift_class_count.toolchain, .drift_class_count.dependency] | @csv' "${tmp}/v_all.json")" != '1,1,1' ]]; then
    echo "selftest: combined change should drift all three classes" >&2; failures=$((failures+1))
  fi

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
    diagnose) shift; cmd_diagnose "$@" ;;
    selftest) shift; cmd_selftest "$@" ;;
    -h|--help|"") usage; [[ -n "${mode}" ]] && exit 0 || exit 2 ;;
    *) usage; die "unknown mode: ${mode}" ;;
  esac
}

main "$@"
