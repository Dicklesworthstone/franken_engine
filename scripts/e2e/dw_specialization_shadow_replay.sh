#!/usr/bin/env bash
# dw_specialization_shadow_replay.sh - replay verifier for the E9
# specialization-lane capstone bundle (bd-fqlfw.9.6).
#
#   bundle <dir> : verify a preserved bundle's content hashes + pass outcome
#   rerun        : re-run the gate into a replay artifact root
set -euo pipefail
root_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$root_dir"

CAP="dw_specialization_shadow"
mode="${1:-bundle}"; shift || true

verify_bundle() {
  local dir="$1"
  [[ -d "$dir" ]] || { echo "replay: bundle dir not found: $dir" >&2; exit 2; }
  local manifest="$dir/run_manifest.json"
  [[ -f "$manifest" ]] || { echo "replay: missing run_manifest.json in $dir" >&2; exit 2; }
  local claim_cmds claim_events have_cmds have_events
  claim_cmds=$(jq -r '.content_hashes.commands_txt' "$manifest")
  claim_events=$(jq -r '.content_hashes.events_jsonl' "$manifest")
  have_cmds=$(sha256sum "$dir/commands.txt" | awk '{print $1}')
  have_events=$(sha256sum "$dir/events.jsonl" | awk '{print $1}')
  if [[ "$claim_cmds" != "$have_cmds" || "$claim_events" != "$have_events" ]]; then
    echo "replay: CONTENT-HASH MISMATCH - bundle tampered or corrupt" >&2
    echo "  commands.txt: manifest=$claim_cmds actual=$have_cmds" >&2
    echo "  events.jsonl: manifest=$claim_events actual=$have_events" >&2
    exit 1
  fi
  # SAFETY-CRITICAL: a certifying E9 capstone bundle must have run the
  # no-elision + safe-mode invariant lane; a bundle without the invariants
  # event is not a certifying bundle for bd-fqlfw.9.6.
  if ! grep -q '"step":"invariants"' "$dir/events.jsonl" \
    && ! grep -q '"invariants"' "$dir/events.jsonl"; then
    echo "replay: bundle lacks the E9 invariants lane (no_ifc_elision/safe_mode)" >&2
    exit 1
  fi
  local outcome
  outcome=$(jq -r '.outcome' "$manifest")
  echo "replay: $CAP bundle $dir verified (outcome=$outcome, source_revision=$(jq -r '.source_revision' "$manifest"))"
  [[ "$outcome" == "pass" ]] || { echo "replay: non-pass outcome ($outcome) - not a certifying bundle" >&2; exit 1; }
}

case "$mode" in
  bundle)
    if [[ $# -ge 1 ]]; then
      verify_bundle "$1"
    else
      latest=""
      if [[ -d "artifacts/$CAP" ]]; then
        while IFS= read -r dir; do
          if [[ -f "$dir/run_manifest.json" ]]; then
            latest="$dir"
            break
          fi
          echo "replay: skipping incomplete bundle $dir (no run_manifest.json)" >&2
        done < <(find "artifacts/$CAP" -mindepth 1 -maxdepth 1 -type d -print | LC_ALL=C sort -r)
      fi
      [[ -n "$latest" ]] || { echo "replay: no complete $CAP bundle found" >&2; exit 2; }
      verify_bundle "$latest"
    fi
    ;;
  rerun)
    DW_ARTIFACT_ROOT="artifacts/$CAP/replay" "./scripts/run_dw_specialization_shadow.sh" ci "$@"
    ;;
  *) echo "usage: $0 [bundle <dir>|rerun]" >&2; exit 2 ;;
esac
