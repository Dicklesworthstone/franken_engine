#!/usr/bin/env bash
set -euo pipefail

# bd-8enww.5.7 (YTBG-E7): replay wrapper for the YTBG release gate.
#
# Runs scripts/run_ytbg_release_gate.sh twice and asserts the VERDICT is
# reproducible: same overall outcome and the same per-lane status set across two
# independent runs. Wall-clock fields (generated_at, duration_s) are expected to
# differ and are excluded from the comparison; the gate's meaning (which lanes
# pass / fail) must not.
#
# Usage: scripts/e2e/ytbg_release_gate_replay.sh [ci]
# Honors the same environment overrides as the gate (CARGO_TARGET_DIR, etc.).

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
GATE="${REPO_ROOT}/scripts/run_ytbg_release_gate.sh"
MODE="${1:-ci}"

command -v python3 >/dev/null 2>&1 || {
  echo "[ytbg-replay] python3 required" >&2
  exit 2
}

REPLAY_ROOT="${YTBG_REPLAY_ROOT:-/tmp/ytbg_release_gate_replay}"
mkdir -p "${REPLAY_ROOT}"

run_once() {
  local tag="$1"
  YTBG_ARTIFACT_ROOT="${REPLAY_ROOT}" YTBG_RUN_ID="replay-${tag}" \
    bash "${GATE}" "${MODE}" || true # capture verdict from the manifest, not the exit code
  echo "${REPLAY_ROOT}/replay-${tag}/run_manifest.json"
}

echo "[ytbg-replay] run A ..."
MANIFEST_A="$(run_once a | tail -n1)"
echo "[ytbg-replay] run B ..."
MANIFEST_B="$(run_once b | tail -n1)"

python3 - "${MANIFEST_A}" "${MANIFEST_B}" <<'PY'
import json, sys

a_path, b_path = sys.argv[1:3]
a = json.load(open(a_path))
b = json.load(open(b_path))

def verdict(m):
    return {
        "outcome": m["outcome"],
        "lanes": {l["lane"]: l["status"] for l in m["lanes"]},
        "required_failed": m["summary"]["required_failed_count"],
    }

va, vb = verdict(a), verdict(b)
if va != vb:
    print("[ytbg-replay] DIVERGENCE:", file=sys.stderr)
    print("  A:", json.dumps(va, sort_keys=True), file=sys.stderr)
    print("  B:", json.dumps(vb, sort_keys=True), file=sys.stderr)
    sys.exit(3)

print(f"[ytbg-replay] reproducible verdict: outcome={va['outcome']} "
      f"lanes={va['lanes']}")
if va["outcome"] != "pass":
    print("[ytbg-replay] gate outcome is not pass; replay is reproducible but the "
          "gate is red", file=sys.stderr)
    sys.exit(3)
print("[ytbg-replay] OK")
PY
