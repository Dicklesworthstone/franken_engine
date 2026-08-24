#!/usr/bin/env bash
# Bridge closeout gate runner — verify one decomposed-parent bead and record
# the native br workflow-gate verdict.
#
# Owning bead: bd-performance-conformance-bridge-tu32j.22.61
#
# Usage:
#   scripts/run_bridge_closeout_gate.sh <bead-id>            # verify + report pass/fail
#   scripts/run_bridge_closeout_gate.sh <bead-id> --check    # verify only, no tracker write
#
# On success records: br gate report <id> --gate bridge_closeout
#                     --provider bridge-closeout-verifier --status pass --to closed
#                     --note "manifest=<hash12> <snapshot-digest> rev=<git-sha>"
# The pass is bound by br to the issue's current status revision; any later
# status change stales it and close re-denies (native stale-revision check).
#
# Fails closed: any verifier violation reports --status fail and exits 1.

set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
BEAD_ID="${1:?usage: run_bridge_closeout_gate.sh <bead-id> [--check]}"
MODE="${2:-}"

if [[ -z "$BEAD_ID" || "$BEAD_ID" == -* ]]; then
  echo "usage: $0 <bead-id> [--check]" >&2
  exit 2
fi

VERIFY="$ROOT_DIR/scripts/bridge_closeout_verify.py"
MANIFEST="$ROOT_DIR/docs/bridge_closeout_manifest_v1.json"
GATE_ID="bridge_closeout"
PROVIDER="bridge-closeout-verifier"

if [[ ! -f "$MANIFEST" ]]; then
  echo "FAIL manifest missing: $MANIFEST" >&2
  exit 2
fi

REPORT_JSON="$(python3 "$VERIFY" --issue "$BEAD_ID" --manifest "$MANIFEST" --json)" || true
OK="$(jq -r '.ok' <<<"$REPORT_JSON")"
DIGEST="$(jq -r '.snapshot_digest' <<<"$REPORT_JSON")"
REVISION="$(git -C "$ROOT_DIR" rev-parse --short HEAD 2>/dev/null || echo unknown)"
NOTE="manifest=$(jq -r '.content_hash' "$MANIFEST" | cut -c8-19) ${DIGEST} rev=${REVISION}"

if [[ "$MODE" == "--check" ]]; then
  jq '{ok, violations}' <<<"$REPORT_JSON"
  if [[ "$OK" != "true" ]]; then
    exit 1
  fi
  echo "check-only: no gate result recorded"
  exit 0
fi

if [[ "$OK" != "true" ]]; then
  echo "DENIED $BEAD_ID — recording gate failure" >&2
  jq -r '.violations[] | "  [\(.code)] \((del(.code) | tojson))"' <<<"$REPORT_JSON" >&2
  br gate report "$BEAD_ID" --gate "$GATE_ID" --provider "$PROVIDER" \
    --status fail --note "$NOTE" --no-auto-import >/dev/null
  exit 1
fi

br gate report "$BEAD_ID" --gate "$GATE_ID" --provider "$PROVIDER" \
  --status pass --to closed --note "$NOTE" --no-auto-import >/dev/null
echo "PASS $BEAD_ID gate=$GATE_ID provider=$PROVIDER note=\"$NOTE\""
echo "next: br close $BEAD_ID --reason \"...\" (close must cite evidence; gate pass stales on any status change)"
